package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"loophid/backend_service"
	"loophid/pkg/client"
	http_server "loophid/pkg/http/server"
	"time"

	"github.com/kkyr/fig"
)

var configFile = flag.String("c", "", "Config file")

type Config struct {
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

	BackendClient struct {
		BackendAddress string `fig:"backend_address" validate:"required"`
		BackendPort    int    `fig:"backend_port" default:"41110"`
		GRPCSSLCert    string `fig:"grpc_ssl_cert"`
		GRPCSSLKey     string `fig:"grpc_ssl_key"`
		GRPCCACert     string `fig:"grpc_ca_cert"`
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

	for _, port := range cfg.HTTPListener.Port {
		go func(listenAddress string) {
			s := http_server.NewHttpServer(c, listenAddress, cfg.HTTPListener.IP)
			fmt.Printf("Starting server on : %s\n", listenAddress)
			log.Fatal(s.Start())
		}(fmt.Sprintf("%s:%d", cfg.HTTPListener.IP, port))
	}

	for _, port := range cfg.HTTPSListener.Port {
		go func(listenAddress string) {
			s := http_server.NewSSLHttpServer(c, listenAddress, cfg.HTTPSListener.SSLCert, cfg.HTTPSListener.SSLKey, cfg.HTTPSListener.IP)
			fmt.Printf("Starting SSL server on : %s\n", listenAddress)
			log.Fatal(s.Start())
		}(fmt.Sprintf("%s:%d", cfg.HTTPSListener.IP, port))
	}

	// Setup the go routing for regularly reporting the status back to the
	// backend.
	statusChan := make(chan bool)
	ticker := time.NewTicker(time.Minute * 5)
	ip := cfg.HTTPSListener.IP
	if ip == "" {
		ip = cfg.HTTPListener.IP
	}
	sReq := backend_service.StatusRequest{
		Ip: ip,
		//ListenPort:    ports,
		//ListenPortSsl: sslPorts,
	}

	go func() {
		for {
			select {
			case <-statusChan:
				ticker.Stop()
				slog.Info("Status channel stopped")
				return
			case <-ticker.C:
				if _, err := c.SendStatus(&sReq); err != nil {
					slog.Warn("error sending status", slog.String("error", err.Error()))
				}
			}
		}
	}()

	<-finish
	statusChan <- true
}
