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
	Alerting struct {
		Interval time.Duration `fig:"interval" default:"2m"`
		Telegram struct {
			ApiKey    string `fig:"api_key"`
			ChannelID int    `fig:"channel_id"`
		} `fig:"telegram"`
	}
	VirusTotal struct {
		ApiKey            string        `fig:"api_key"`
		HttpClientTimeout time.Duration `fig:"http_timeout" default:"2m"`
	} `fig:"virustotal"`
	Metrics struct {
		ListenAddress string `fig:"listen_address" default:"localhost:8998"`
	} `fig:"prometheus"`
	WhoisManager struct {
		ClientTimeout       time.Duration `fig:"client_timeout" default:"2s"`
		CacheExpirationTime time.Duration `fig:"cache_expiration_time" default:"12h"`
		MaxAttempts         int           `fig:"max_attempts" default:"3"`
	} `fig:"whois_manager"`
}
