package describer

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"lophiid/pkg/analysis"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"sync"
	"time"
)

type DescriptionManager interface {
	MaybeAddNewHash(hash string, req *models.Request) error
	Start()
}

// CachedDescriptionManager is a manager for request descriptions. It caches
// descriptions in memory so that database calls are minimal.
type CachedDescriptionManager struct {
	cache        *util.StringMapCache[struct{}]
	dbClient     database.DatabaseClient
	llmQueueMap  map[string]QueueEntry
	queueLock    sync.RWMutex
	llmManager   *llm.LLMManager
	eventManager analysis.IpEventManager
	llmBatchSize int
	bgChan       chan bool
	metrics      *DescriberMetrics
}

type QueueEntry struct {
	RequestDescription *models.RequestDescription
	Request            *models.Request
}

type LLMResult struct {
	Description       string `json:"description"`
	Malicious         string `json:"malicious"`
	VulnerabilityType string `json:"vulnerability_type"`
	Application       string `json:"application"`
	CVE               string `json:"cve"`
}

const LLMSystemPrompt = `
Our security system receive a potential malicous HTTP request which is given
below. Describe what the request tries to do and what application it targets. If the request is malicious
then tell me what kind of vulnerability it tries to exploit. Do not include the targetted server hostname, IP or port in the description.

Your answer needs to be in the form of a raw JSON object that is not formatted for displaying. The keys of the json object are:

description: store here your answer but keep it one or two paragraphs long
malicious: Use the string "yes" if the request is likely malicious (e.g. it contains a payload, vulnerability type). Use the string "no" if the request does not appear malicious.
vulnerability type: a string with the type of vulnerability if malicious. Use the string "unknown" if the request is malicious but you don't know the vulnerability type. Use "none" if the request is not malicious.
application: a string with the full application/device name that is being targetted or "unknown" if you don't know
cve: the relevant CVE or an empty string if you do not know.

The request was:
`

func GetNewCachedDescriptionManager(dbClient database.DatabaseClient, llmManager *llm.LLMManager, eventManager analysis.IpEventManager, cacheTimeout time.Duration, metrics *DescriberMetrics, batchSize int) *CachedDescriptionManager {

	cache := util.NewStringMapCache[struct{}]("CmpHash cache", cacheTimeout)
	cache.Start()

	return &CachedDescriptionManager{
		dbClient:     dbClient,
		cache:        cache,
		llmQueueMap:  make(map[string]QueueEntry),
		llmBatchSize: batchSize,
		llmManager:   llmManager,
		bgChan:       make(chan bool),
		metrics:      metrics,
		eventManager: eventManager,
	}
}

func (b *CachedDescriptionManager) Start() {
	slog.Info("Starting base hash manager")
	go b.QueueProcessor()
}

func (b *CachedDescriptionManager) Stop() {
	slog.Info("Stopping base hash manager")
	b.bgChan <- true
}

// MaybeAddNewHash add the hash to the cache and database if necessary. Also
// schedules an LLM description for the hash.
func (b *CachedDescriptionManager) MaybeAddNewHash(hash string, req *models.Request) error {
	// First check the cache
	_, err := b.cache.Get(hash)
	if err == nil {
		return nil
	}

	// Next check the database
	res, err := b.dbClient.SearchRequestDescription(0, 1, fmt.Sprintf("cmp_hash:%s", hash))
	if err != nil {
		return fmt.Errorf("failed to check database for request description %s: %w", hash, err)
	}

	if len(res) == 1 {
		// It's already in the database so update the cache to reflect this.
		b.cache.Store(hash, struct{}{})
		return nil
	}

	// If we get here then we have not seen this hash before so we need to add
	// to the database and additionally put it in the queue for LLM description
	// generation.
	bh := &models.RequestDescription{
		CmpHash:          hash,
		ExampleRequestID: req.ID,
		ReviewStatus:     "UNREVIEWED",
	}

	dm, err := b.dbClient.Insert(bh)
	if err != nil {
		return fmt.Errorf("failed to insert description: %s: %w", hash, err)
	}

	b.queueLock.Lock()
	b.llmQueueMap[hash] = QueueEntry{
		RequestDescription: dm.(*models.RequestDescription),
		Request:            req,
	}
	b.queueLock.Unlock()

	b.cache.Store(hash, struct{}{})
	return nil
}

func (b *CachedDescriptionManager) GenerateLLMDescriptions(entries []*QueueEntry) error {

	var prompts []string
	promptMap := make(map[string]*QueueEntry, len(entries))

	for _, entry := range entries {
		slog.Debug("Describing request for URI", slog.String("uri", entry.Request.Uri))
		prompt := fmt.Sprintf("%s\n%s", LLMSystemPrompt, entry.Request.Raw)
		promptMap[prompt] = entry
		prompts = append(prompts, prompt)
	}

	start := time.Now()
	result, err := b.llmManager.CompleteMultiple(prompts, false)

	if err != nil {
		return fmt.Errorf("failed to complete LLM request: %w", err)
	}

	b.metrics.completeMultipleResponsetime.Observe(time.Since(start).Seconds())
	for prompt, completion := range result {
		var llmResult LLMResult
		if err := json.Unmarshal([]byte(completion), &llmResult); err != nil {
			return fmt.Errorf("failed to parse LLM result: %w, result: %s", err, result)
		}

		bh := promptMap[prompt].RequestDescription
		bh.AIDescription = llmResult.Description
		bh.AIVulnerabilityType = llmResult.VulnerabilityType
		bh.AIApplication = llmResult.Application
		bh.AIMalicious = llmResult.Malicious
		bh.AICVE = llmResult.CVE

		if err := b.dbClient.Update(bh); err != nil {
			return fmt.Errorf("failed to insert description: %w", err)
		}

		req := promptMap[prompt].Request
		// If the rule is 0 then no existing rule matched. In this case if the AI
		// says the request was malicious then we want to raise an event.
		if req.RuleID == 0 && llmResult.Malicious == "yes" {
			b.eventManager.AddEvent(&models.IpEvent{
				IP:         req.SourceIP,
				HoneypotIP: req.HoneypotIP,
				Source:     constants.IpEventSourceAI,
				SourceRef:  fmt.Sprintf("%d", req.ID),
				Type:       constants.IpEventAttacked,
				Details:    "AI marked request as malicious",
			})
		}
	}

	return nil
}

func (b *CachedDescriptionManager) QueueProcessor() {
	for {

		entries := []*QueueEntry{}

		b.queueLock.Lock()
		if len(b.llmQueueMap) > 0 {
			cnt := 0
			for k, v := range b.llmQueueMap {
				entries = append(entries, &v)
				delete(b.llmQueueMap, k)
				cnt += 1
				if cnt > b.llmBatchSize {
					break
				}
			}
		}
		b.queueLock.Unlock()

		if len(entries) > 0 {
			if err := b.GenerateLLMDescriptions(entries); err != nil {
				slog.Error("failed to generate LLM description", slog.String("error", err.Error()))
			}
		} else {
			time.Sleep(time.Second)
		}

		select {
		case <-b.bgChan:
			slog.Info("Description hash queue processor done")
			return
		default:
			b.metrics.pendingRequestsGauge.Set(float64(len(b.llmQueueMap)))
		}
	}
}

type FakeDescriptionManager struct {
	addNewHashError error
}

func (f *FakeDescriptionManager) MaybeAddNewHash(hash string, req *models.Request) error {
	return f.addNewHashError
}

func (f *FakeDescriptionManager) Start() {}
