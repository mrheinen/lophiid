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

import (
	"fmt"
	"lophiid/pkg/llm"
	"time"
)

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
			SessionIPRateWindow           time.Duration `fig:"session_ip_rate_window" default:"1h"`
			SessionIPBucketDuration       time.Duration `fig:"session_ip_bucket_duration" default:"1m"`
			MaxSessionIPRequestsPerWindow int           `fig:"max_session_ip_requests_per_window" default:"1000"`
			MaxSessionIPRequestsPerBucket int           `fig:"max_session_ip_requests_per_bucket" default:"50"`

			SourceIPRateWindow           time.Duration `fig:"source_ip_rate_window" default:"24h"`
			SourceIPBucketDuration       time.Duration `fig:"source_ip_bucket_duration" default:"1h"`
			MaxSourceIPRequestsPerWindow int           `fig:"max_source_ip_requests_per_window" default:"5000"`
			MaxSourceIPRequestsPerBucket int           `fig:"max_source_ip_requests_per_bucket" default:"3000"`

			URIRateWindow           time.Duration `fig:"uri_rate_window" default:"1h"`
			URIBucketDuration       time.Duration `fig:"uri_bucket_duration" default:"1m"`
			MaxURIRequestsPerWindow int           `fig:"max_uri_requests_per_window" default:"2000"`
			MaxURIRequestsPerBucket int           `fig:"max_uri_requests_per_bucket" default:"100"`
		} `fig:"ratelimiter"`

		Advanced struct {
			ContentCacheDuration  time.Duration `fig:"content_cache_duration" default:"30m"`
			DownloadCacheDuration time.Duration `fig:"download_cache_duration" default:"5m"`
			// Max downloads per IP per every 5 minutes
			MaxDownloadsPerIP int `fig:"max_downloads_per_ip" default:"50"`
			// Upload limits. By default allow 3MB uploads. Maximum of 5 per 30
			// minutes per unique IP.
			MaxUploadSizeBytes         int           `fig:"max_upload_size_bytes" default:"3000000"`
			MaxUploadsPerIP            int           `fig:"max_uploads_per_ip" default:"5"`
			MaxUploadsPerIPWindow      time.Duration `fig:"max_uploads_per_ip_window" default:"30m"`

			PingCacheDuration          time.Duration `fig:"ping_cache_duration" default:"5m"`
			DownloadIPCountersDuration time.Duration `fig:"download_ip_counters_duration" default:"5m"`
			HoneypotCacheDuration      time.Duration `fig:"honeypot_cache_duration" default:"15m"`
			PayloadCmpHashDuration     time.Duration `fig:"payload_cmp_hash_duration" default:"45m"`
			ConsecutivePayloadDuration time.Duration `fig:"consecutive_payload_duration" default:"20m"`
			QueriesRunnerInterval      time.Duration `fig:"stored_queries_run_interval" default:"1h"`
			RequestsQueueSize          int           `fig:"requests_queue_size" default:"500"`
			MaintenanceRoutineInterval time.Duration `fig:"maintenance_routine_interval" default:"1m"`
			// After how long of no communication a session times out.
			SessionTrackingTimeout time.Duration `fig:"session_tracking_timeout" default:"1h"`
			// The default content that honeypots are configured with upon first
			// seeing them.
			HoneypotDefaultContentID int `fig:"honeypot_default_content_id" default:"1"`
			// DebugIPs is a list of IP networks (in CIDR notation) that will receive
			// debug headers in responses. When a request comes from an IP within one
			// of these networks, the response will include X-Lophiid-Request-ID and
			// X-Lophiid-Session-ID headers. Use /32 for single IPs (e.g., "10.0.0.1/32")
			// or network ranges (e.g., "192.168.1.0/24").
			DebugIPs []string `fig:"debug_ips"`
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
		Interval            time.Duration `fig:"interval" default:"2m"`
		WebInterfaceAddress string        `fig:"web_interface_address" default:""`
		Telegram            struct {
			ApiKey    string `fig:"api_key"`
			ChannelID int    `fig:"channel_id"`
		} `fig:"telegram"`
	}
	VirusTotal struct {
		ApiKey              string        `fig:"api_key"`
		HttpClientTimeout   time.Duration `fig:"http_timeout" default:"2m"`
		CacheExpirationTime time.Duration `fig:"cache_expiration_time" default:"96h"`
	} `fig:"virustotal"`
	Yara struct {
		LogFile              string `fig:"log_file" default:"yara.log" `
		LogLevel             string `fig:"log_level" default:"debug" `
		MetricsListenAddress string `fig:"metrics_listen_address" default:"localhost:8997" `
		PrepareCommand       string `fig:"prepare_command" default:"" `
	} `fig:"yara"`
	Metrics struct {
		ListenAddress string `fig:"listen_address" default:"localhost:8998"`
	} `fig:"prometheus"`
	WhoisManager struct {
		ClientTimeout       time.Duration `fig:"client_timeout" default:"2s"`
		CacheExpirationTime time.Duration `fig:"cache_expiration_time" default:"12h"`
		MaxAttempts         int           `fig:"max_attempts" default:"6"`
	} `fig:"whois_manager"`

	AI struct {
		MaxInputCharacters int `fig:"max_input_characters" default:"10000"`

		// LLMConfigs holds named LLM configurations that can be referenced by other settings.
		LLMConfigs []NamedLLMConfig `fig:"llm_configs"`

		Responder struct {
			Enable    bool   `fig:"enable" default:"0"`
			LLMConfig string `fig:"llm_config"`
		} `fig:"llm_responder"`
		ShellEmulation struct {
			Enable    bool              `fig:"enable" default:"0"`
			LLMConfig string            `fig:"llm_config"`
			RateLimit AIRateLimitConfig `fig:"rate_limit"`
		} `fig:"shell_emulation"`
		CodeEmulation struct {
			Enable    bool              `fig:"enable" default:"0"`
			LLMConfig string            `fig:"llm_config"`
			RateLimit AIRateLimitConfig `fig:"rate_limit"`
		} `fig:"code_emulation"`
		FileEmulation struct {
			Enable    bool              `fig:"enable" default:"0"`
			LLMConfig string            `fig:"llm_config"`
			RateLimit AIRateLimitConfig `fig:"rate_limit"`
		} `fig:"file_emulation"`
		SqlEmulation struct {
			Enable    bool              `fig:"enable" default:"0"`
			LLMConfig string            `fig:"llm_config"`
			RateLimit AIRateLimitConfig `fig:"rate_limit"`
		} `fig:"sql_emulation"`
		CodeInterpreter struct {
			Enable    bool   `fig:"enable" default:"0"`
			LLMConfig string `fig:"llm_config"`
		} `fig:"code_interpreter"`

		Triage struct {
			Describer struct {
				Enable               bool          `fig:"enable" default:"1"`
				LLMConfig            string        `fig:"llm_config"`
				IgnoreRegexList      []string      `fig:"ignore_regex_list"`
				LogFile              string        `fig:"log_file" default:"triage.log"`
				LogLevel             string        `fig:"log_level" default:"debug"`
				MetricsListenAddress string        `fig:"metrics_listen_address" default:"localhost:8999"`
				CacheExpirationTime  time.Duration `fig:"cache_expiration_time" default:"8h"`
			} `fig:"describer"`
			PreProcess struct {
				LLMConfig string `fig:"llm_config"`
			} `fig:"preprocess"`
		} `fig:"triage"`
	} `fig:"ai"`
}

// AIRateLimitConfig holds rate limiting configuration for an AI emulation function.
type AIRateLimitConfig struct {
	RateWindow           time.Duration `fig:"rate_window" default:"1h"`
	BucketDuration       time.Duration `fig:"bucket_duration" default:"1m"`
	MaxRequestsPerWindow int           `fig:"max_requests_per_window" default:"100"`
	MaxRequestsPerBucket int           `fig:"max_requests_per_bucket" default:"20"`
}

// NamedLLMConfig wraps an LLMManagerConfig with a name for referencing.
type NamedLLMConfig struct {
	Name   string               `fig:"name"`
	Config llm.LLMManagerConfig `fig:"config"`
}

// GetLLMConfig returns the LLM configuration for the given name.
// Returns an error if the configuration is not found.
func (c *Config) GetLLMConfig(name string) (llm.LLMManagerConfig, error) {
	if len(c.AI.LLMConfigs) == 0 {
		return llm.LLMManagerConfig{}, fmt.Errorf("no LLM configs defined")
	}
	for _, cfg := range c.AI.LLMConfigs {
		if cfg.Name == name {
			return cfg.Config, nil
		}
	}
	return llm.LLMManagerConfig{}, fmt.Errorf("LLM config %q not found", name)
}
