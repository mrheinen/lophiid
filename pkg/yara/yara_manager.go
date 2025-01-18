package yara

import (
	"fmt"
	"log/slog"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util/constants"
	"os"
	"os/exec"
	"strings"
	"time"
)

const UnpackedExtension = ".unpacked"

type YaraManager struct {
	dbClient       database.DatabaseClient
	rulesLocation  string
	metrics        *YaraMetrics
	prepareCommand string
}

func NewYaraManager(dbClient database.DatabaseClient, rulesLocation string, prepareCommand string, metrics *YaraMetrics) *YaraManager {
	return &YaraManager{
		dbClient:       dbClient,
		rulesLocation:  rulesLocation,
		metrics:        metrics,
		prepareCommand: prepareCommand,
	}
}

// GetPendingScanList returns a list of downloads that need to be scanned
func (d *YaraManager) GetPendingScanList(limit int64) ([]models.Download, error) {
	retDownloads := []models.Download{}
	res, err := d.dbClient.SearchDownloads(0, limit, "yara_status:PENDING")
	if err != nil {
		return retDownloads, fmt.Errorf("error searching yara: %s", err)
	}

	return res, nil
}

func (d *YaraManager) PrepareDownloadsForScan(downloads *[]models.Download) {
}

// ScanDownloads scans the downloads using the given Yara instance.
// If the downloaded file exists with the .unpacked extention then this will be
// used for the scan instead of the original file. Such an unpacked file could,
// for example, be created by the prepareCommand.
func (d *YaraManager) ScanDownloads(yw Yara, downloads *[]models.Download) (map[*models.Download][]YaraResult, error) {
	rets := make(map[*models.Download][]YaraResult)

	for _, dl := range *downloads {
		start := time.Now()

		// Run the command to prepare the download for the scan.
		if d.prepareCommand != "" {
			cmd := exec.Command(d.prepareCommand, dl.FileLocation)
			if err := cmd.Run(); err != nil {
				slog.Error("Error running command", slog.String("command", d.prepareCommand), slog.String("error", err.Error()))
			}
		}

		// If the file exists with the .unpacked extension then this is used to do
		// the yara scan.
		unpackedLocation := fmt.Sprintf("%s%s", dl.FileLocation, UnpackedExtension)
		fileToScan := dl.FileLocation

		if _, err := os.Stat(unpackedLocation); err == nil {
			slog.Debug("Unpacked file found", slog.String("file", unpackedLocation))
			dl.YaraScannedUnpacked = true
			fileToScan = unpackedLocation
		}

		if _, err := os.Stat(fileToScan); err != nil {
			slog.Error("File is missing", slog.String("file", dl.FileLocation), slog.String("error", err.Error()))
			continue
		}

		slog.Info("Scanning", slog.String("file", fileToScan))
		res, err := yw.ScanFile(fileToScan)
		if err != nil {
			slog.Error("Error scanning", slog.String("file", dl.FileLocation), slog.String("error", err.Error()))
			return rets, fmt.Errorf("error scanning %s: %w", dl.FileLocation, err)
		}

		d.metrics.scanFileDuration.Observe(time.Since(start).Seconds())

		rets[&dl] = res
	}

	return rets, nil
}

func (d *YaraManager) StoreYaraResults(results map[*models.Download][]YaraResult) error {
	for dl, res := range results {
		for _, resEntry := range res {
			newYara := models.Yara{
				DownloadID: dl.ID,
				Identifier: resEntry.Identifier,
			}

			newYara.Tags = append(newYara.Tags, resEntry.Tags...)
			for _, md := range resEntry.Metadata {

				switch strings.ToLower(md.Identifier) {
				case "author":
					newYara.Author = md.Value.(string)
				case "description":
					newYara.Description = md.Value.(string)
				case "malpedia_reference":
					newYara.MalpediaReference = md.Value.(string)
				case "malpedia_license":
					newYara.MalpediaLicense = md.Value.(string)
				case "malpedia_sharing":
					newYara.MalpediaSharing = md.Value.(string)
				case "reference":
					newYara.Reference = md.Value.(string)
				case "date":
					newYara.Date = md.Value.(string)
				case "id":
					newYara.EID = md.Value.(string)
				}
			}

			_, err := d.dbClient.Insert(&newYara)
			if err != nil {
				return fmt.Errorf("error inserting yara: %+v %w", newYara, err)
			}
		}
	}
	return nil
}

func (d *YaraManager) MarkDownloadsDone(downloads *[]models.Download) error {

	for _, dl := range *downloads {
		dl.YaraStatus = constants.YaraStatusTypeDone
		if err := d.dbClient.Update(&dl); err != nil {
			slog.Error("Error updating download", slog.String("error", err.Error()))
			return fmt.Errorf("error updating download: %w", err)
		}
	}
	return nil
}

func (d *YaraManager) ProcessDownloadsAndScan(batchSize int64) (int, error) {
	pending, err := d.GetPendingScanList(batchSize)
	if err != nil {
		return 0, fmt.Errorf("error getting pending downloads: %w", err)
	}

	if len(pending) == 0 {
		return 0, nil
	}

	slog.Info("Processing", slog.Int("pending", len(pending)))

	yaraInstance := YaraxWrapper{}
	yaraInstance.Init()
	if err = yaraInstance.LoadRulesFromDirectory(d.rulesLocation); err != nil {
		return 0, fmt.Errorf("error loading rules: %w", err)
	}

	scanResults, err := d.ScanDownloads(&yaraInstance, &pending)
	if err != nil {
		return 0, fmt.Errorf("error scanning: %w", err)
	}

	if len(scanResults) == 0 {
		slog.Debug("No results found")
		return len(pending), nil
	}

	if err = d.StoreYaraResults(scanResults); err != nil {
		return len(pending), fmt.Errorf("error storing yara: %w", err)
	}

	if err = d.MarkDownloadsDone(&pending); err != nil {
		return len(pending), fmt.Errorf("error marking downloads done: %w", err)
	}

	return len(pending), nil
}
