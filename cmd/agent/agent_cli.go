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
package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"lophiid/pkg/agent"
	"lophiid/pkg/backend"
	"lophiid/pkg/bootstrap"
	"lophiid/pkg/util"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/mrheinen/p0fclient"
)

type Config struct {
	General struct {
		PublicIP  string `fig:"public_ip" validate:"required"`
		LogLevel  string `fig:"log_level" default:"debug"`
		RunAsUser string `fig:"user"`
		ChrootDir string `fig:"chroot_dir"`
		LogFile   string `fig:"log_file" validate:"required"`
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
	P0f struct {
		SocketLocation string        `fig:"socket_location"`
		SendInterval   time.Duration `fig:"send_interval" default:"1m"`
	} `fig:"p0f"`
	Pinger struct {
		PingTimeout time.Duration `fig:"ping_timeout" default:"1m"`
	} `fig:"pinger"`
	BackendClient struct {
		StatusInterval time.Duration `fig:"status_interval" default:"10s"`
		AuthToken      string        `fig:"auth_token" valiate:"required"`
		BackendAddress string        `fig:"ip" validate:"required"`
		BackendPort    int           `fig:"port" default:"41110"`
		GRPCSSLCert    string        `fig:"grpc_ssl_cert"`
		GRPCSSLKey     string        `fig:"grpc_ssl_key"`
		GRPCCACert     string        `fig:"grpc_ca_cert"`
	} `fig:"backend_client" validate:"required"`
}

func main() {
	var cfg Config

	cleanup, err := bootstrap.Initialize(&cfg, bootstrap.InitConfig{
		LogFileExtractor: func(c any) string {
			return c.(*Config).General.LogFile
		},
		LogLevelExtractor: func(c any) string {
			return c.(*Config).General.LogLevel
		},
	})
	if err != nil {
		fmt.Printf("Initialization failed: %s\n", err)
		return
	}
	defer cleanup()

	if cfg.HTTPSListener.IP == "" && cfg.HTTPListener.IP == "" {
		slog.Warn("No listener IPs specified\n")
		return
	}

	// Create the backend client.
	var c backend.BackendClient
	if cfg.BackendClient.GRPCCACert != "" && cfg.BackendClient.GRPCSSLCert != "" && cfg.BackendClient.GRPCSSLKey != "" {
		slog.Info("Creating secure backend client.", slog.String("server", cfg.BackendClient.BackendAddress))
		c = &backend.SecureBackendClient{
			CACert:     cfg.BackendClient.GRPCCACert,
			ClientCert: cfg.BackendClient.GRPCSSLCert,
			ClientKey:  cfg.BackendClient.GRPCSSLKey,
			ServerFQDN: cfg.BackendClient.BackendAddress,
		}

		if err := c.Connect(net.JoinHostPort(cfg.BackendClient.BackendAddress, fmt.Sprintf("%d", cfg.BackendClient.BackendPort)), cfg.BackendClient.AuthToken); err != nil {
			log.Fatalf("%s", err)
		}
	} else {
		slog.Info("Creating insecure backend client.", slog.String("server", cfg.BackendClient.BackendAddress))
		c = &backend.InsecureBackendClient{}
		if err := c.Connect(net.JoinHostPort(cfg.BackendClient.BackendAddress, fmt.Sprintf("%d", cfg.BackendClient.BackendPort)), cfg.BackendClient.AuthToken); err != nil {
			log.Fatalf("Could not connect: %s", err)
		}
	}

	defer c.Disconnect()

	finish := make(chan bool)

	var httpServers []*agent.HttpServer
	for _, port := range cfg.HTTPListener.Port {
		httpServers = append(httpServers, agent.NewHttpServer(c, net.JoinHostPort(cfg.HTTPListener.IP, fmt.Sprintf("%d", port)), cfg.HTTPListener.IP))
	}

	for _, port := range cfg.HTTPSListener.Port {
		httpServers = append(httpServers, agent.NewSSLHttpServer(c, net.JoinHostPort(cfg.HTTPListener.IP, fmt.Sprintf("%d", port)), cfg.HTTPSListener.SSLCert, cfg.HTTPSListener.SSLKey, cfg.HTTPListener.IP))
	}

	// Create the http client. It will allow long timeouts to download from slow
	// IoT devices. Additionally it will not care about secure SSL.
	insecureHttpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	downloadHttpClient := &http.Client{Transport: insecureHttpTransport, Timeout: cfg.Downloader.HttpClientTimeout}

	var p0fRunner *agent.P0fRunnerImpl
	p0fRunner = nil
	if cfg.P0f.SocketLocation != "" {
		if _, err := os.Stat(cfg.P0f.SocketLocation); errors.Is(err, os.ErrNotExist) {
			log.Fatal("p0f socket location does not exist")
		}

		slog.Info("Opening p0f socket", slog.String("socket_file", cfg.P0f.SocketLocation))
		p0fclient := p0fclient.NewP0fClient(cfg.P0f.SocketLocation)

		if err := p0fclient.Connect(); err != nil {
			slog.Warn("Failed to connect to p0f socket", slog.String("socket_file", cfg.P0f.SocketLocation), slog.String("error", err.Error()))
		}
		p0fRunner = agent.NewP0fRunnerImpl(p0fclient)
	}

	pinger := agent.NewProbingPingRunner(cfg.Pinger.PingTimeout)
	agent := agent.NewAgent(c, httpServers, downloadHttpClient, p0fRunner, pinger, cfg.BackendClient.StatusInterval, cfg.P0f.SendInterval, cfg.Pinger.PingTimeout, cfg.General.PublicIP)
	agent.Start()

	// Sleep some time to let the HTTP servers initialize.
	time.Sleep(2 * time.Second)

	if cfg.General.RunAsUser != "" && cfg.General.ChrootDir != "" {
		err := util.DropPrivilegesAndChroot(cfg.General.RunAsUser, cfg.General.ChrootDir)
		if err != nil {
			slog.Warn("Failed to drop privileges and chroot", slog.String("error", err.Error()))
		}
	}

	<-finish
}
