package agent

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"loophid/backend_service"
	"loophid/pkg/client"
	"net/http"
	"net/http/httputil"
	"time"

	http_server "loophid/pkg/http/server"
)

type Agent struct {
	backendClient  client.BackendClient
	httpServers    []*http_server.HttpServer
	reportIP       string
	httpClient     *http.Client
	statusChan     chan bool
	statusInterval time.Duration
}

func NewAgent(backendClient client.BackendClient, httpServers []*http_server.HttpServer, httpClient *http.Client, statusInterval time.Duration, reportIP string) *Agent {
	return &Agent{
		backendClient:  backendClient,
		httpServers:    httpServers,
		reportIP:       reportIP,
		httpClient:     httpClient,
		statusChan:     make(chan bool),
		statusInterval: statusInterval,
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
					Ip: a.reportIP,
				})

				if err != nil {
					slog.Warn("error sending status", slog.String("error", err.Error()))
				} else {
					a.HandleCommandsFromResponse(resp)
				}
			}
		}
	}()

	return nil
}

func (a *Agent) Stop() {
	a.statusChan <- true

}

func (a *Agent) DownloadToBuffer(request *backend_service.CommandDownloadFile) (*backend_service.DownloadInfo, error) {
	var downloadInfo backend_service.DownloadInfo
	downloadInfo.OriginalUrl = request.OriginalUrl
	downloadInfo.Ip = request.Ip
	downloadInfo.HoneypotIp = a.reportIP

	startTime := time.Now()
	req, err := http.NewRequest("GET", request.Url, nil)
	if err != nil {
		return &downloadInfo, fmt.Errorf("creating request for URL: %s, err %s", request.Url, err)
	}
	req.Host = request.HostHeader
	req.Header.Set("User-Agent", request.UserAgent)

	downloadInfo.Url = request.Url
	downloadInfo.UserAgent = request.UserAgent

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

