package scanner

import (
	"crypto/rand"
	"encoding/hex"
	"hash/fnv"
	"io"
	"net/http"
	"strings"
	"sync"
)

type WildcardDetector struct {
	client    *http.Client
	readBytes int
	mu        sync.RWMutex

	hashes map[uint64]bool

	sizesByStatus map[int]map[int64]bool
}

func NewWildcardDetector(client *http.Client, readBytes int) *WildcardDetector {
	if readBytes <= 0 {
		readBytes = 16 << 10
	}
	return &WildcardDetector{
		client:        client,
		readBytes:     readBytes,
		hashes:        make(map[uint64]bool),
		sizesByStatus: make(map[int]map[int64]bool),
	}
}

func (d *WildcardDetector) Probe(baseURL string, n int, userAgent string, headers map[string]string) {
	if n <= 0 {
		n = 3
	}

	base := strings.TrimRight(baseURL, "/")

	type probeResult struct {
		status int
		size   int64
		hash   uint64
	}
	results := make([]probeResult, 0, n)

	for i := 0; i < n; i++ {
		randPath := randomPath()
		url := base + "/" + randPath

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		h := fnv.New64a()
		normalized := normalizeBody(body)
		h.Write(normalized)
		hash := h.Sum64()

		results = append(results, probeResult{
			status: resp.StatusCode,
			size:   int64(len(body)),
			hash:   hash,
		})
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	realNotFound := true
	for _, r := range results {
		if r.status != 404 {
			realNotFound = false
			break
		}
	}
	if realNotFound {
		return
	}

	hashCount := make(map[uint64]int)
	sizeCountByStatus := make(map[int]map[int64]int)
	for _, r := range results {
		hashCount[r.hash]++
		if sizeCountByStatus[r.status] == nil {
			sizeCountByStatus[r.status] = make(map[int64]int)
		}
		sizeCountByStatus[r.status][r.size]++
	}
	for h, c := range hashCount {
		if c >= 2 {
			d.hashes[h] = true
		}
	}
	for code, counts := range sizeCountByStatus {
		for size, c := range counts {
			if c < 2 {
				continue
			}
			if d.sizesByStatus[code] == nil {
				d.sizesByStatus[code] = make(map[int64]bool)
			}
			d.sizesByStatus[code][size] = true
		}
	}
}

func (d *WildcardDetector) Hashes() map[uint64]bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make(map[uint64]bool, len(d.hashes))
	for k, v := range d.hashes {
		out[k] = v
	}
	return out
}

func (d *WildcardDetector) SizesByStatus() map[int]map[int64]bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	out := make(map[int]map[int64]bool, len(d.sizesByStatus))
	for code, sizes := range d.sizesByStatus {
		out[code] = make(map[int64]bool, len(sizes))
		for size, ok := range sizes {
			out[code][size] = ok
		}
	}
	return out
}

func (d *WildcardDetector) Summary() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	sizeCount := 0
	for _, sizes := range d.sizesByStatus {
		sizeCount += len(sizes)
	}
	if len(d.hashes) == 0 && sizeCount == 0 {
		return "none (target respects proper 404)"
	}
	return "detected " + itoa(len(d.hashes)) + " wildcard hash(es), " + itoa(sizeCount) + " size fingerprint(s)"
}

func randomPath() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func normalizeBody(b []byte) []byte {
	s := string(b)
	s = strings.ToLower(s)
	var out strings.Builder
	out.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !prevSpace {
				out.WriteByte(' ')
				prevSpace = true
			}
		} else {
			out.WriteRune(r)
			prevSpace = false
		}
	}
	return []byte(out.String())
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func HashBody(body []byte) uint64 {
	h := fnv.New64a()
	h.Write(normalizeBody(body))
	return h.Sum64()
}
