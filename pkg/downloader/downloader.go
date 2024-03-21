package downloader

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"loophid/pkg/database"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// User agent to send with the requests. We use wget because it is often used in
// command injections to download code from a server.
var (
	userAgent = "Wget/1.13.4 (linux-gnu)"
	schemeReg = regexp.MustCompile(`^[a-z]+:`)
)

type Downloader interface {
	CleanupTargetFileDir(subdir string, targetFile string) error
	FromUrl(reqId int64, fromUrl string, targetFile string, wg *sync.WaitGroup) (database.Download, []byte, error)
	PepareTargetFileDir(subdir string) (string, error)
}

type HTTPDownloader struct {
	downloadDir     string
	privateIPBlocks []*net.IPNet
	httpClient      *http.Client
}

type FakeDownloader struct {
	DownloadToReturn   database.Download
	DataToReturn       []byte
	ErrorToReturn      error
	TargetFileToReturn string
}

func (f *FakeDownloader) CleanupTargetFileDir(subdir string, targetFile string) error {
	return f.ErrorToReturn
}
func (f *FakeDownloader) PepareTargetFileDir(subdir string) (string, error) {
	return f.TargetFileToReturn, f.ErrorToReturn
}
func (f *FakeDownloader) FromUrl(reqId int64, fromUrl string, targetFile string, wg *sync.WaitGroup) (database.Download, []byte, error) {
	return f.DownloadToReturn, f.DataToReturn, f.ErrorToReturn
}

// NewDownloader returns a Downloader instance. The downloads will be put in sub
// directories of downloadDir. It is worth to set a relative long timeout
// on the http client because IoT devices can be slow.
func NewHTTPDownloader(downloadDir string, httpClient *http.Client) *HTTPDownloader {
	d := HTTPDownloader{
		downloadDir: downloadDir,
		httpClient:  httpClient,
	}

	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			slog.Warn("cannot parse IPs", slog.String("error", err.Error()))
			return nil
		}
		d.privateIPBlocks = append(d.privateIPBlocks, block)
	}
	return &d
}

// isPrivateIP checks if an IP is private or not.
func (d *HTTPDownloader) isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range d.privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func (d *HTTPDownloader) getIPForUrl(targetUrl string) (string, net.IP, int, error) {
	var rHost string
	var rIP net.IP
	rHostPort := 0

	u, err := url.Parse(targetUrl)
	if err != nil {
		return rHost, rIP, rHostPort, err
	}

	rHost = u.Host
	if strings.Contains(rHost, ":") {
		parts := strings.Split(rHost, ":")
		// TODO: handle IPv6 properly.
		if len(parts) != 2 {
			return rHost, rIP, rHostPort, fmt.Errorf("cannot handle host: %s", rHost)
		}
		rHost = parts[0]
		rHostPort, err = strconv.Atoi(parts[1])
		if err != nil {
			return rHost, rIP, rHostPort, fmt.Errorf("cannot handle host port: %d", rHostPort)
		}
	}

	rIP = net.ParseIP(rHost)
	if rIP == nil {
		netIps, err := net.LookupIP(rHost)
		if err != nil {
			return rHost, rIP, rHostPort, err
		}
		rIP = netIps[0]
	}
	return rHost, rIP, rHostPort, err
}

func (d *HTTPDownloader) PepareTargetFileDir(subdir string) (string, error) {
	targetDir := fmt.Sprintf("%s/%s", d.downloadDir, subdir)

	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		// Due to concurrency, it is possible that between the check for whether the
		// directory exists and creating one, the directory is already created.
		// Therefore we double check here that any error during creation is no
		// ErrExist which we'll allow.
		if err := os.Mkdir(targetDir, 0755); err != nil && !os.IsExist(err) {
			return "", err
		}
	}
	return fmt.Sprintf("%s/%d", targetDir, rand.Intn(100000)), nil
}

func (d *HTTPDownloader) CleanupTargetFileDir(subdir string, targetFile string) error {
	targetDir := fmt.Sprintf("%s/%s", d.downloadDir, subdir)
	if _, err := os.Stat(targetFile); err == nil {
		if err := os.Remove(targetFile); err != nil {
			return err
		}
	}

	// Remove the directory and ignore errors. Specifically because the directory
	// might not be empty in which case it's ok for this operation to fail.
	if _, err := os.Stat(targetDir); err == nil {
		os.Remove(targetDir)
	}
	return nil
}

func (d *HTTPDownloader) FromUrl(reqId int64, fromUrl string, targetFile string, wg *sync.WaitGroup) (database.Download, []byte, error) {
	var dInfo database.Download
	defer wg.Done()

	slog.Debug("downloading", slog.String("url", fromUrl))

	// If no scheme is in front of the URL, we will default to http:// because
	// this is what wget and curl also do.
	if schemeReg.FindString(fromUrl) == "" {
		fromUrl = fmt.Sprintf("http://%s", fromUrl)
	}

	host, ip, port, err := d.getIPForUrl(fromUrl)
	if err != nil {
		return dInfo, nil, err
	}

	dInfo.Host = host
	dInfo.IP = ip.String()
	dInfo.Port = int64(port)
	dInfo.OriginalUrl = fromUrl
	dInfo.RequestID = reqId

	if d.isPrivateIP(ip) {
		return dInfo, nil, fmt.Errorf("IP is private: %s", ip.String())
	}

	// Modify the URL so we connect to the IP we resolved and checked.
	u, _ := url.Parse(fromUrl)
	ipStr := ip.String()
	// Handle IPv6 IPs.
	if ip.To4() == nil {
		ipStr = fmt.Sprintf("[%s]", ipStr)
	}

	if port == 0 {
		u.Host = ipStr
	} else {
		u.Host = fmt.Sprintf("%s:%d", ipStr, port)
	}

	dInfo.UsedUrl = u.String()
	dInfo.FileLocation = targetFile

	out, err := os.Create(targetFile)
	if err != nil {
		return dInfo, nil, fmt.Errorf("creating file: %s", err)
	}

	defer out.Close()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return dInfo, nil, fmt.Errorf("creating request for URL: %s, err %s", u.String(), err)
	}
	req.Host = host
	req.Header.Set("User-Agent", userAgent)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return dInfo, nil, fmt.Errorf("fetching file: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return dInfo, nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		dInfo.ContentType = contentType
	}

	rawRespBytes, err := httputil.DumpResponse(resp, false)
	if err != nil {
		slog.Debug("could no dump raw response", slog.String("error", err.Error()))
		// We allow this error and do not return here. The raw response really is
		// optional and not worth do ditch all the other information for.
	} else {
		dInfo.RawHttpResponse = string(rawRespBytes)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return dInfo, nil, fmt.Errorf("reading response: %s", err)
	}

	sum := sha256.Sum256(respBytes)
	dInfo.SHA256sum = fmt.Sprintf("%x", sum)

	bytesWritten, err := io.Copy(out, bytes.NewReader(respBytes))
	if err != nil {
		return dInfo, respBytes, err
	}

	dInfo.Size = bytesWritten

	data := fmt.Sprintf("URL: %s\nHost: %s\n", u.String(), host)
	os.WriteFile(fmt.Sprintf("%s.txt", targetFile), []byte(data), 0644)
	return dInfo, respBytes, nil
}
