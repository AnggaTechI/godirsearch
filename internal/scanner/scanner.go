package scanner

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"godirsearch/internal/filter"
	"godirsearch/internal/output"
)

type Scanner struct {
	cfg     *Config
	filter  *filter.Filter
	writer  output.Writer
	clients []*http.Client 
	limiter *AdaptiveLimiter

	// channels
	jobs    chan job
	results chan output.Result
	done    chan struct{}

	// state
	wg      sync.WaitGroup
	abortMu sync.Mutex
	aborted bool
	ctx     context.Context
	cancel  context.CancelFunc

	// stats (atomic)
	totalJobs  int64
	processed  int64
	foundCount int64
	errorCount int64
	bytesRead  int64
	startTime  time.Time

	// recursion tracking
	recursionMu sync.Mutex
	scannedDirs map[string]bool 

	pendingJobs int64
	jobsClosed  int32 

	OnResult func(output.Result)
}

type job struct {
	url   string
	depth int
}

func New(cfg *Config, f *filter.Filter, w output.Writer) (*Scanner, error) {
	proxies := cfg.ProxyList
	if cfg.Proxy != "" && len(proxies) == 0 {
		proxies = []string{cfg.Proxy}
	}
	if len(proxies) == 0 {
		proxies = []string{""} // no-proxy
	}

	clients := make([]*http.Client, 0, len(proxies))
	for _, p := range proxies {
		c, err := buildHTTPClient(cfg, p)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if cfg.MaxRuntime > 0 {
		ctx, cancel = context.WithTimeout(ctx, cfg.MaxRuntime)
	}

	return &Scanner{
		cfg:         cfg,
		filter:      f,
		writer:      w,
		clients:     clients,
		limiter:     NewAdaptiveLimiter(cfg.MaxRate),
		jobs:        make(chan job, cfg.Threads*4),
		results:     make(chan output.Result, cfg.Threads*2),
		done:        make(chan struct{}),
		ctx:         ctx,
		cancel:      cancel,
		scannedDirs: make(map[string]bool),
	}, nil
}

func (s *Scanner) Run() error {
	s.startTime = time.Now()

	for _, tgt := range s.cfg.Targets {
		s.probeWildcard(tgt)
		if s.isAborted() {
			return nil
		}
	}

	for i := 0; i < s.cfg.Threads; i++ {
		s.wg.Add(1)
		go s.worker(i)
	}

	collectDone := make(chan struct{})
	go s.collector(collectDone)
	go s.feeder()

	s.wg.Wait()
	close(s.results)
	<-collectDone
	close(s.done)

	return nil
}

func (s *Scanner) pushJob(j job) bool {
	if atomic.LoadInt32(&s.jobsClosed) == 1 {
		return false
	}
	atomic.AddInt64(&s.pendingJobs, 1)
	select {
	case <-s.ctx.Done():
		atomic.AddInt64(&s.pendingJobs, -1)
		s.tryCloseJobs()
		return false
	case s.jobs <- j:
		atomic.AddInt64(&s.totalJobs, 1)
		return true
	}
}

func (s *Scanner) jobDone() {
	if atomic.AddInt64(&s.pendingJobs, -1) == 0 {
		s.tryCloseJobs()
	}
}

func (s *Scanner) tryCloseJobs() {
	if atomic.CompareAndSwapInt32(&s.jobsClosed, 0, 1) {
		close(s.jobs)
	}
}

func (s *Scanner) probeWildcard(target string) {
	if s.cfg.WildcardProbes <= 0 {
		return
	}
	d := NewWildcardDetector(s.clients[0], s.cfg.BodyReadBytes)
	ua := pickOne(s.cfg.UserAgents)
	d.Probe(target, s.cfg.WildcardProbes, ua, s.cfg.Headers)
	// merge ke filter (thread-safe)
	s.filter.MergeWildcard(d.Hashes(), d.SizesByStatus())
}

func (s *Scanner) feeder() {
	for _, tgt := range s.cfg.Targets {
		base := strings.TrimRight(tgt, "/")

		subdirs := s.cfg.Subdirs
		if len(subdirs) == 0 {
			subdirs = []string{""}
		}

		for _, sub := range subdirs {
			sub = strings.Trim(sub, "/")
			prefix := base
			if sub != "" {
				prefix = base + "/" + sub
			}

			for _, p := range s.cfg.Paths {
				path := strings.TrimLeft(p, "/")
				full := prefix + "/" + path
				if !s.pushJob(job{url: full, depth: 0}) {
					return
				}
			}
		}
	}

	if atomic.LoadInt64(&s.pendingJobs) == 0 {
		s.tryCloseJobs()
	}
}

func (s *Scanner) worker(idx int) {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case j, ok := <-s.jobs:
			if !ok {
				return
			}
			if s.isAborted() {
				return
			}
			s.processJob(j, idx)
		}
	}
}

func (s *Scanner) processJob(j job, workerIdx int) {
	defer s.jobDone()
	s.limiter.Wait()
	if s.cfg.Delay > 0 {
		time.Sleep(s.cfg.Delay)
	}

	var lastErr error
	var result *output.Result

	for attempt := 0; attempt <= s.cfg.Retries; attempt++ {
		result, lastErr = s.probe(j, workerIdx)
		if lastErr == nil {
			break
		}
		backoff := time.Duration(100*(1<<attempt)) * time.Millisecond
		if backoff > 5*time.Second {
			backoff = 5 * time.Second
		}
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(backoff):
		}
	}

	atomic.AddInt64(&s.processed, 1)

	if lastErr != nil {
		atomic.AddInt64(&s.errorCount, 1)
		if s.cfg.ExitOnError {
			s.abort()
		}
		return
	}

	if result != nil {
		result.Timestamp = time.Now()
		select {
		case <-s.ctx.Done():
		case s.results <- *result:
		}

		if s.cfg.Recursive && j.depth < s.cfg.MaxDepth {
			s.maybeRecurse(j, result)
		}
	}
}

func (s *Scanner) probe(j job, workerIdx int) (*output.Result, error) {
	client := s.clients[workerIdx%len(s.clients)]

	method := s.cfg.Method
	if method == "" {
		method = "GET"
	}

	var body io.Reader
	if s.cfg.Body != "" {
		body = strings.NewReader(s.cfg.Body)
	}

	req, err := http.NewRequestWithContext(s.ctx, method, j.url, body)
	if err != nil {
		return nil, err
	}

	ua := pickOne(s.cfg.UserAgents)
	if ua == "" {
		ua = "godirsearch/0.2"
	}
	req.Header.Set("User-Agent", ua)

	for k, v := range s.cfg.Headers {
		req.Header.Set(k, v)
	}
	if s.cfg.Cookie != "" {
		req.Header.Set("Cookie", s.cfg.Cookie)
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, bodyFullyRead := readBodySample(resp, s.cfg.BodyReadBytes)
	atomic.AddInt64(&s.bytesRead, int64(len(bodyBytes)))
	duration := time.Since(start)

	size := int64(len(bodyBytes))
	if resp.ContentLength >= 0 {
		size = resp.ContentLength
	}

	redirect := ""
	if loc, err := resp.Location(); err == nil {
		redirect = loc.String()
	}

	if resp.StatusCode == 429 || resp.StatusCode == 503 {
		s.limiter.Penalize()
	}

	info := &filter.ResponseInfo{
		StatusCode: resp.StatusCode,
		Size:       size,
		Body:       bodyBytes,
		Redirect:   redirect,
		BodyHash:   HashBody(bodyBytes),
	}
	action := s.filter.Evaluate(info)

	switch action {
	case filter.ActionAbort:
		s.abort()
		return nil, nil
	case filter.ActionDrop:
		return nil, nil
	}

	ctype := resp.Header.Get("Content-Type")
	var words, lines int
	if isTextContent(ctype) && bodyFullyRead {
		words, lines = countWordsLines(bodyBytes)
	}

	return &output.Result{
		URL:         j.url,
		StatusCode:  resp.StatusCode,
		Size:        size,
		Redirect:    redirect,
		ContentType: ctype,
		Words:       words,
		Lines:       lines,
		Duration:    duration.Milliseconds(),
	}, nil
}

func isTextContent(ctype string) bool {
	if ctype == "" {
		return true 
	}
	ctype = strings.ToLower(ctype)
	textPrefixes := []string{
		"text/", "application/json", "application/xml",
		"application/javascript", "application/xhtml",
		"application/x-www-form-urlencoded",
	}
	for _, p := range textPrefixes {
		if strings.HasPrefix(ctype, p) {
			return true
		}
	}
	return false
}

func readBodySample(resp *http.Response, maxBytes int) ([]byte, bool) {
	if resp == nil || resp.Body == nil {
		return nil, true
	}
	if resp.Request != nil && strings.EqualFold(resp.Request.Method, http.MethodHead) {
		io.Copy(io.Discard, resp.Body)
		return nil, true
	}
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		io.Copy(io.Discard, resp.Body)
		return nil, true
	}
	if maxBytes <= 0 {
		maxBytes = 16 << 10
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes+1)))
	fullyRead := true
	if len(body) > maxBytes {
		body = body[:maxBytes]
		fullyRead = false
	}
	return body, fullyRead
}

func (s *Scanner) maybeRecurse(parent job, r *output.Result) {
	isDir := s.cfg.ForceRecursive ||
		strings.HasSuffix(r.URL, "/") ||
		(r.StatusCode >= 300 && r.StatusCode < 400 && strings.HasSuffix(r.Redirect, "/"))

	if !isDir {
		return
	}

	statusOK := false
	for _, c := range s.cfg.RecursionStatus {
		if r.StatusCode == c {
			statusOK = true
			break
		}
	}
	if !statusOK {
		return
	}

	newBase := strings.TrimRight(r.URL, "/")
	if r.Redirect != "" {
		newBase = strings.TrimRight(r.Redirect, "/")
	}

	s.recursionMu.Lock()
	if s.scannedDirs[newBase] {
		s.recursionMu.Unlock()
		return
	}
	s.scannedDirs[newBase] = true
	s.recursionMu.Unlock()

	if s.cfg.WildcardProbes > 0 {
		s.probeWildcard(newBase)
	}

	go func() {
		for _, p := range s.cfg.Paths {
			path := strings.TrimLeft(p, "/")
			full := newBase + "/" + path
			if !s.pushJob(job{url: full, depth: parent.depth + 1}) {
				return
			}
		}
	}()
}

func (s *Scanner) collector(done chan struct{}) {
	defer close(done)
	for r := range s.results {
		atomic.AddInt64(&s.foundCount, 1)
		if s.OnResult != nil {
			s.OnResult(r)
		}
		if err := s.writer.Write(r); err != nil {
			fmt.Printf("write error: %v\n", err)
		}
	}
}

func (s *Scanner) abort() {
	s.abortMu.Lock()
	defer s.abortMu.Unlock()
	if !s.aborted {
		s.aborted = true
		s.cancel()
	}
}

func (s *Scanner) Stop() {
	s.abort()
}

func (s *Scanner) isAborted() bool {
	s.abortMu.Lock()
	defer s.abortMu.Unlock()
	return s.aborted
}

type Stats struct {
	Total       int64
	Processed   int64
	Found       int64
	Errors      int64
	BytesRead   int64
	Rate        float64 // req/sec
	Elapsed     time.Duration
	CurrentRate float64
	Throttled   int64
}

func (s *Scanner) Stats() Stats {
	elapsed := time.Since(s.startTime)
	processed := atomic.LoadInt64(&s.processed)
	rate := 0.0
	if elapsed.Seconds() > 0 {
		rate = float64(processed) / elapsed.Seconds()
	}
	return Stats{
		Total:       atomic.LoadInt64(&s.totalJobs),
		Processed:   processed,
		Found:       atomic.LoadInt64(&s.foundCount),
		Errors:      atomic.LoadInt64(&s.errorCount),
		BytesRead:   atomic.LoadInt64(&s.bytesRead),
		Rate:        rate,
		Elapsed:     elapsed,
		CurrentRate: s.limiter.CurrentRate(),
		Throttled:   s.limiter.ThrottleCount(),
	}
}

func pickOne(pool []string) string {
	if len(pool) == 0 {
		return ""
	}
	if len(pool) == 1 {
		return pool[0]
	}
	return pool[rand.Intn(len(pool))]
}

func countWordsLines(b []byte) (int, int) {
	if len(b) == 0 {
		return 0, 0
	}
	words := 0
	lines := 1
	inWord := false
	for _, c := range b {
		if c == '\n' {
			lines++
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if inWord {
				words++
				inWord = false
			}
		} else {
			inWord = true
		}
	}
	if inWord {
		words++
	}
	return words, lines
}
