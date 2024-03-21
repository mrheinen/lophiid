package agent

import (
	"log"
	"log/slog"
	"loophid/backend_service"
	"loophid/pkg/client"
	"time"

	http_server "loophid/pkg/http/server"
)

type Agent struct {
	backendClient client.BackendClient
	httpServers   []*http_server.HttpServer
	reportIP      string
	statusChan    chan bool
}

func NewAgent(backendClient client.BackendClient, httpServers []*http_server.HttpServer, reportIP string) *Agent {
	return &Agent{
		backendClient: backendClient,
		httpServers:   httpServers,
		reportIP:      reportIP,
		statusChan:    make(chan bool),
	}
}

func (a *Agent) Start() error {

	slog.Info("Starting HTTP(S) servers")
	for _, s := range a.httpServers {
		go func(server *http_server.HttpServer) {
			// TODO: find a more elegant way
			log.Fatal(server.Start())
		}(s)
	}

	return nil
}

func (a *Agent) Stop() {
	a.statusChan <- true

}

func (a *Agent) SendStatus() {

	sReq := backend_service.StatusRequest{
		Ip: a.reportIP,
	}

	ticker := time.NewTicker(time.Minute * 5)
	go func() {
		for {
			select {
			case <-a.statusChan:
				ticker.Stop()
				slog.Info("Status channel stopped")
				return
			case <-ticker.C:
				if _, err := a.backendClient.SendStatus(&sReq); err != nil {
					slog.Warn("error sending status", slog.String("error", err.Error()))
				}
			}
		}
	}()

}

func (a *Agent) SendDownload() {

}
