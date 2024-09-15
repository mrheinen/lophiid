// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
package agent

import (
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"lophiid/backend_service"
	"lophiid/pkg/backend"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/mrheinen/magicmime"
)

type Agent struct {
	backendClient   backend.BackendClient
	httpServers     []*HttpServer
	reportIP        string
	httpClient      *http.Client
	statusChan      chan bool
	statusInterval  time.Duration
	contextChan     chan bool
	contextInterval time.Duration
	mimeMu          sync.Mutex
	mimeInstance    *magicmime.Decoder
	ipCache         *util.StringMapCache[bool]
	p0fRunner       P0fRunner
}

func NewAgent(backendClient backend.BackendClient, httpServers []*HttpServer, httpClient *http.Client, p0fRunner P0fRunner, statusInterval time.Duration, contextInterval time.Duration, reportIP string) *Agent {

	mi, _ := magicmime.NewDecoder(magicmime.MAGIC_MIME_TYPE)
	ipCache := util.NewStringMapCache[bool]("IP cache", time.Hour*2)
	ipCache.Start()

	return &Agent{
		backendClient:   backendClient,
		httpServers:     httpServers,
		reportIP:        reportIP,
		httpClient:      httpClient,
		statusChan:      make(chan bool),
		statusInterval:  statusInterval,
		contextChan:     make(chan bool),
		contextInterval: contextInterval,
		mimeInstance:    mi,
		ipCache:         ipCache,
		p0fRunner:       p0fRunner,
	}
}

func (a *Agent) Start() error {

	slog.Info("Starting HTTP(S) servers")
	for _, s := range a.httpServers {
		go func(server *HttpServer) {
			// TODO: find a more elegant way
			if a.p0fRunner != nil {
				log.Fatal(server.StartWithIPCache(a.ipCache))
			} else {
				log.Fatal(server.Start())
			}
		}(s)
	}

	// Start the status interval submissions
	ticker := time.NewTicker(a.statusInterval)
	go func() {
		for {
			select {
			case <-a.statusChan:
				ticker.Stop()
				slog.Info("Status channel stopped")
				return
			case <-ticker.C:
				resp, err := a.backendClient.SendStatus(&backend_service.StatusRequest{
					Ip:      a.reportIP,
					Version: constants.LophiidVersion,
				})

				if err != nil {
					slog.Warn("error sending status", slog.String("error", err.Error()))
				} else {
					a.HandleCommandsFromResponse(resp)
				}
			}
		}
	}()

	// The final part is only for when the p0frunner is initialized.
	if a.p0fRunner == nil {
		return nil
	}

	// Start the context submissions
	conTicker := time.NewTicker(a.contextInterval)
	go func() {
		for {
			select {
			case <-a.contextChan:
				ticker.Stop()
				slog.Info("Context channel stopped")
				return
			case <-conTicker.C:
				if err := a.SendContext(); err != nil {
					slog.Warn("error sending context", slog.String("error", err.Error()))
				}
				expCount := a.ipCache.CleanExpired()
				slog.Debug("Cleaned expired IPs", slog.Int64("count", expCount))
			}
		}
	}()

	return nil
}

func (a *Agent) Stop() {
	a.statusChan <- true
	a.contextChan <- true
}

func bytesToString(bytes [32]uint8) string {
	var sb strings.Builder
	for i := 0; i < len(bytes) && bytes[i] != 0x00; i++ {
		sb.WriteByte(bytes[i])
	}

	return sb.String()

}

// SendContext sends context information for source IPs to the backend.
// Currently it just sends p0f query results. In the future this will be
// extended with things such as port scan data.
func (a *Agent) SendContext() error {

	if a.p0fRunner == nil {
		return nil
	}
	// We get a map representation of the cache. Since this is a copy, we might be
	// working with older data the soon we get it. This is ok. The worst that
	// happens is that we send data too often.
	ipMap := a.ipCache.GetAsMap()
	for ipAddr, wasSubmitted := range ipMap {
		if wasSubmitted {
			continue
		}

		pr, err := a.p0fRunner.QueryIP(ipAddr)
		if err != nil {
			if errors.Is(err, ErrP0fQueryNoResult) {
				slog.Debug("p0f found no match for IP", slog.String("ip", ipAddr))
				a.ipCache.Store(ipAddr, true)
				continue
			}

			slog.Warn("error querying p0f", slog.String("error", err.Error()))
			// TODO: maybe we need to check the error type and conditionally
			// 'continue' here.
			continue
		}

		req := backend_service.SendSourceContextRequest{
			SourceIp: ipAddr,
			Context: &backend_service.SendSourceContextRequest_P0FResult{
				P0FResult: &backend_service.P0FResult{
					FirstSeen:        pr.FirstSeen,
					LastSeen:         pr.LastSeen,
					TotalCount:       pr.TotalCount,
					UptimeMinutes:    pr.UptimeMinutes,
					UptimeDays:       pr.UpModDays,
					Distance:         uint32(pr.Distance),
					LastNatDetection: pr.LastNat,
					LastOsChange:     pr.LastChg,
					OsMatchQuality:   uint32(pr.OsMatchQ),
					OsName:           bytesToString(pr.OsName),
					OsVersion:        bytesToString(pr.OsFlavor),
					HttpName:         bytesToString(pr.HttpName),
					HttpFlavor:       bytesToString(pr.HttpFlavor),
					LinkType:         bytesToString(pr.LinkType),
					Language:         bytesToString(pr.Language),
				},
			},
		}

		if _, err = a.backendClient.SendSourceContext(&req); err != nil {
			slog.Warn("error sending context RPC", slog.String("error", err.Error()))
			// Continue and try to submit the others. Because in this case the cahce
			// is not updated; we will try again next time.
			continue
		}

		slog.Debug("submitted context for IP", slog.String("ip", ipAddr))
		a.ipCache.Store(ipAddr, true)
	}
	return nil
}

func (a *Agent) DownloadToBuffer(request *backend_service.CommandDownloadFile) (*backend_service.DownloadInfo, error) {
	downloadInfo := backend_service.DownloadInfo{
		OriginalUrl: request.OriginalUrl,
		Ip:          request.Ip,
		HoneypotIp:  a.reportIP,
		HostHeader:  request.HostHeader,
		Url:         request.Url,
		UserAgent:   request.UserAgent,
	}

	startTime := time.Now()
	req, err := http.NewRequest(http.MethodGet, request.Url, nil)
	if err != nil {
		return &downloadInfo, fmt.Errorf("creating request for URL: %s, err %s", request.Url, err)
	}
	req.Host = request.HostHeader
	req.Header.Set("User-Agent", request.UserAgent)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return &downloadInfo, fmt.Errorf("fetching file for url: %s, err %s", request.Url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &downloadInfo, fmt.Errorf("invalid response code: %d err %s", resp.StatusCode, err)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		downloadInfo.ContentType = contentType
	}

	rawRespBytes, err := httputil.DumpResponse(resp, false)
	if err != nil {
		slog.Debug("could no dump raw response", slog.String("error", err.Error()))
		// We allow this error and do not return here. The raw response really is
		// optional and not worth do ditch all the other information for.
	} else {
		downloadInfo.RawHttpResponse = string(rawRespBytes)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return &downloadInfo, fmt.Errorf("reading response: %s", err)
	}

	a.mimeMu.Lock()
	detectedMimeType, err := a.mimeInstance.TypeByBuffer(respBytes)
	a.mimeMu.Unlock()
	if err != nil {
		slog.Warn("unable to determine mime", slog.String("error", err.Error()))
		detectedMimeType = "application/octet-stream"
	}

	downloadInfo.DetectedContentType = detectedMimeType
	downloadInfo.DurationSec = time.Since(startTime).Seconds()
	downloadInfo.Data = respBytes
	return &downloadInfo, nil
}

func (a *Agent) DownloadFileAndSubmit(request *backend_service.CommandDownloadFile) error {
	slog.Info("Downloading URL", slog.String("url", request.Url))
	downloadInfo, err := a.DownloadToBuffer(request)
	if err != nil {
		return fmt.Errorf("could not download: %w", err)
	}

	slog.Info("Sending data to backend")
	uploadRequest := backend_service.UploadFileRequest{
		RequestId: request.RequestId,
		Info:      downloadInfo,
	}

	_, err = a.backendClient.HandleUploadFile(&uploadRequest)
	if err != nil {
		return fmt.Errorf("error doing upload rpc: %w", err)
	}

	return nil
}

func (a *Agent) HandleCommandsFromResponse(resp *backend_service.StatusResponse) error {
	if len(resp.Command) == 0 {
		return nil
	}

	slog.Info("Handling commands", slog.Int("amount", len(resp.Command)))

	for _, cmd := range resp.Command {
		switch c := cmd.Command.(type) {
		case *backend_service.Command_DownloadCmd:
			go func(dCmd *backend_service.CommandDownloadFile) {
				slog.Info("Download Command", slog.String("command", fmt.Sprintf("%+v", dCmd)))
				err := a.DownloadFileAndSubmit(dCmd)
				if err != nil {
					slog.Info("got error downloading", slog.String("error", err.Error()))
				}
			}(c.DownloadCmd)

		case nil:
			return nil
		default:
			return fmt.Errorf("unknown type: %+v", c)
		}
	}

	return nil
}
