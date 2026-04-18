package scanner

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type Config struct {
	// Target
	Targets []string

	// Dictionary
	Paths []string 

	// HTTP settings
	Method         string
	UserAgents     []string 
	Headers        map[string]string
	Cookie         string
	Body           string
	FollowRedirect bool
	MaxRedirects   int

	// Concurrency & timing
	Threads     int
	Timeout     time.Duration
	MaxRate     int 
	Delay       time.Duration
	Retries     int
	MaxRuntime  time.Duration 
	ExitOnError bool

	// Recursion
	Recursive       bool
	DeepRecursive   bool
	ForceRecursive  bool
	MaxDepth        int
	RecursionStatus []int

	// Proxy
	Proxy     string
	ProxyList []string 

	// Connection
	HTTP2     bool
	TLSVerify bool

	// Subdirs
	Subdirs []string

	// Wildcard detection
	WildcardProbes int // default 3

	BodyReadBytes int

	// Session/resume
	SessionFile string
}

func buildHTTPClient(cfg *Config, proxyURL string) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !cfg.TLSVerify,
			MinVersion:         tls.VersionTLS12,
		},
		MaxIdleConns:          cfg.Threads * 4,
		MaxIdleConnsPerHost:   cfg.Threads * 2,
		MaxConnsPerHost:       cfg.Threads * 2,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
		DisableCompression:    false,
		ForceAttemptHTTP2:     cfg.HTTP2,
	}

	if proxyURL != "" {
		pu, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("proxy URL tidak valid %q: %w", proxyURL, err)
		}
		transport.Proxy = http.ProxyURL(pu)
	}

	if cfg.HTTP2 {
		transport.ForceAttemptHTTP2 = true
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	if !cfg.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		max := cfg.MaxRedirects
		if max <= 0 {
			max = 5
		}
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= max {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}

	return client, nil
}
