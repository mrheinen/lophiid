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
package backend

import "time"

type Config struct {
	Backend struct {
		LogLevel  string `fig:"log_level" default:"debug"`
		LogFile   string `fig:"log_file" validate:"required"`
		RunAsUser string `fig:"user"`
		ChrootDir string `fig:"chroot_dir"`

		Database struct {
			Url                string `fig:"url" validate:"required"`
			MaxOpenConnections int    `fig:"max_open_connections" default:"20"`
			MinOpenConnections int    `fig:"min_open_connections" default:"5"`
		} `fig:"database" validation:"required"`
		Listener struct {
			ListenAddress string `fig:"listen_address" default:"localhost:41110"`
			SSLCert       string `fig:"ssl_cert"`
			SSLKey        string `fig:"ssl_key"`
			CACert        string `fig:"ssl_ca_cert"`
		} `fig:"listener" validate:"required"`
		Downloader struct {
			MalwareDownloadDir string `fig:"malware_download_dir" validate:"required"`
			MaxDownloadSizeMB  int    `fig:"max_download_size_mb" default:"200"`
		} `fig:"downloader"`
		RateLimiter struct {
			RateWindow           time.Duration `fig:"rate_window" default:"1h"`
			BucketDuration       time.Duration `fig:"bucket_duration" default:"1m"`
			MaxRequestsPerWindow int           `fig:"max_requests_per_window" default:"1000"`
			MaxRequestsPerBucket int           `fig:"max_requests_per_bucket" default:"50"`
		} `fig:"ratelimiter"`

		Advanced struct {
			ContentCacheDuration       time.Duration `fig:"content_cache_duration" default:"30m"`
			DownloadCacheDuration      time.Duration `fig:"download_cache_duration" default:"5m"`
			AttackTrackingDuration     time.Duration `fig:"attack_tracking_duration" default:"7d"`
			QueriesRunnerInterval      time.Duration `fig:"stored_queries_run_interval" default:"1h"`
			RequestsQueueSize          int           `fig:"requests_queue_size" default:"500"`
			MaintenanceRoutineInterval time.Duration `fig:"maintenance_routine_interval" default:"1m"`
		} `fig:"advanced"`
	} `fig:"backend"`
	Analysis struct {
		// Determines how long information for an IP will be cached before writing
		// it to the database. During that time the information will be updated with
		// new events if they happen.
		IpCacheDuration time.Duration `fig:"ip_cache_duration" default:"15m"`
		// How many events there can be in the queue. If this is exceeded then it
		// will start blocking some logic in the backend so keep this number high
		// and monitor the queue size with prometheus/grafana.
		IpEventQueueSize int `fig:"ip_event_queue_size" default:"5000"`
		// Determines how often the scan detection logic will look at the events in
		// the cache. The value should be shorted than the IpCacheDuration
		ScanMonitorInterval time.Duration `fig:"scan_monitor_interval" default:"5m"`
		// Determines how long (approximately) the scan detection logic will keep
		// aggregating scan events into a cached version before writing it to the db.
		// So with the default, if there is a super slow scan, you will get an event
		// every ~hour.
		AggregateScanWindow time.Duration `fig:"scan_aggregation_window" default:"1h"`
	} `fig:"analysis"`
	Scripting struct {
		// The allowed commands.
		AllowedCommands []string      `fig:"allowed_commands"`
		CommandTimeout  time.Duration `fig:"command_timeout" default:"10s"`
	} `fig:"scripting"`
	Alerting struct {
		Interval time.Duration `fig:"interval" default:"2m"`
		Telegram struct {
			ApiKey    string `fig:"api_key"`
			ChannelID int    `fig:"channel_id"`
		} `fig:"telegram"`
	}
	VirusTotal struct {
		ApiKey              string        `fig:"api_key"`
		HttpClientTimeout   time.Duration `fig:"http_timeout" default:"2m"`
		CacheExpirationTime time.Duration `fig:"cache_expiration_time" default:"96h"`
	} `fig:"virustotal"`
	Metrics struct {
		ListenAddress string `fig:"listen_address" default:"localhost:8998"`
	} `fig:"prometheus"`
	WhoisManager struct {
		ClientTimeout       time.Duration `fig:"client_timeout" default:"2s"`
		CacheExpirationTime time.Duration `fig:"cache_expiration_time" default:"12h"`
		MaxAttempts         int           `fig:"max_attempts" default:"6"`
	} `fig:"whois_manager"`

	Responder struct {
		Enable               bool          `fig:"enable" default:"0"`
		ApiLocation          string        `fig:"api_location" default:"http://localhost:8000/v1"`
		ApiKey               string        `fig:"api_key"`
		CacheExpirationTime  time.Duration `fig:"cache_expiration_time" default:"24h"`
		LLMCompletionTimeout time.Duration `fig:"llm_completion_timeout" default:"1m"`
	} `fig:"responder"`
}
