package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"loophid/pkg/agent"
	"loophid/pkg/client"
	http_server "loophid/pkg/http/server"
	"net/http"
	"time"

	"github.com/kkyr/fig"
)

var configFile = flag.String("c", "", "Config file")

type Config struct {
	General struct {
		PublicIP string `fig:"public_ip" validate:"required"`
	} `fig:"general"`
	HTTPListener struct {
		IP   string `fig:"ip"`
		Port []int  `fig:"port"`
	} `fig:"http_listener"`
	HTTPSListener struct {
		IP      string `fig:"ip"`
		SSLCert string `fig:"ssl_cert"`
		SSLKey  string `fig:"ssl_key"`
		Port    []int  `fig:"port"`
	} `fig:"https_listener"`

	Downloader struct {
		HttpClientTimeout time.Duration `fig:"http_client_timeout" default:"10m"`
	} `fig:"downloader"`
	BackendClient struct {
		StatusInterval time.Duration `fig:"status_interval" default:"10s"`
		BackendAddress string        `fig:"ip" validate:"required"`
		BackendPort    int           `fig:"port" default:"41110"`
		GRPCSSLCert    string        `fig:"grpc_ssl_cert"`
		GRPCSSLKey     string        `fig:"grpc_ssl_key"`
		GRPCCACert     string        `fig:"grpc_ca_cert"`
	} `fig:"backend_client" validate:"required"`
}

func main() {

	flag.Parse()

	var cfg Config
	if err := fig.Load(&cfg, fig.File(*configFile)); err != nil {
		fmt.Printf("Could not parse config: %s\n", err)
		return
	}

	if cfg.HTTPSListener.IP == "" && cfg.HTTPListener.IP == "" {
		fmt.Printf("No listener IPs specified\n")
		return
	}

	// Create the backend client.
	var c client.BackendClient
	if cfg.BackendClient.GRPCCACert != "" && cfg.BackendClient.GRPCSSLCert != "" && cfg.BackendClient.GRPCSSLKey != "" {
		log.Printf("Creating secure backend client. Server: %s", cfg.BackendClient.BackendAddress)
		c = &client.SecureBackendClient{
			CACert:     cfg.BackendClient.GRPCCACert,
			ClientCert: cfg.BackendClient.GRPCSSLCert,
			ClientKey:  cfg.BackendClient.GRPCSSLKey,
			ServerFQDN: cfg.BackendClient.BackendAddress,
		}
		if err := c.Connect(fmt.Sprintf("%s:%d", cfg.BackendClient.BackendAddress, cfg.BackendClient.BackendPort)); err != nil {
			log.Fatalf("%s", err)
		}
	} else {
		log.Printf("Creating insecure backend client. Server: %s", cfg.BackendClient.BackendAddress)
		c = &client.InsecureBackendClient{}
		if err := c.Connect(fmt.Sprintf("%s:%d", cfg.BackendClient.BackendAddress, cfg.BackendClient.BackendPort)); err != nil {
			log.Fatalf("%s", err)
		}
	}

	defer c.Disconnect()

	finish := make(chan bool)

	var httpServers []*http_server.HttpServer
	for _, port := range cfg.HTTPListener.Port {
		httpServers = append(httpServers, http_server.NewHttpServer(c, fmt.Sprintf("%s:%d", cfg.HTTPListener.IP, port), cfg.HTTPListener.IP))
	}

	for _, port := range cfg.HTTPSListener.Port {
		httpServers = append(httpServers, http_server.NewSSLHttpServer(c, fmt.Sprintf("%s:%d", cfg.HTTPListener.IP, port), cfg.HTTPSListener.SSLCert, cfg.HTTPSListener.SSLKey, cfg.HTTPListener.IP))
	}

	// Create the http client. It will allow long timeouts to download from slow
	// IoT devices. Additionally it will not care about secure SSL.
	insecureHttpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	downloadHttpClient := &http.Client{Transport: insecureHttpTransport, Timeout: cfg.Downloader.HttpClientTimeout}
	agent := agent.NewAgent(c, httpServers, downloadHttpClient, cfg.BackendClient.StatusInterval, cfg.General.PublicIP)
	agent.Start()

	<-finish
}
