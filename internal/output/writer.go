package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL         string    `json:"url"`
	StatusCode  int       `json:"status"`
	Size        int64     `json:"size"`
	Redirect    string    `json:"redirect,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
	Words       int       `json:"words,omitempty"`
	Lines       int       `json:"lines,omitempty"`
	Duration    int64     `json:"duration_ms"`
	Timestamp   time.Time `json:"timestamp"`
}

type Writer interface {
	Write(r Result) error
	Close() error
}

type MultiWriter struct {
	writers []Writer
	mu      sync.Mutex
}

func NewMulti(ws ...Writer) *MultiWriter { return &MultiWriter{writers: ws} }

func (m *MultiWriter) Write(r Result) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, w := range m.writers {
		if err := w.Write(r); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiWriter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	for _, w := range m.writers {
		if err := w.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type plainWriter struct {
	f  *os.File
	mu sync.Mutex
}

func NewPlain(path string) (Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(f, "# godirsearch results - %s\n", time.Now().Format(time.RFC3339))
	return &plainWriter{f: f}, nil
}

func (w *plainWriter) Write(r Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	line := fmt.Sprintf("[%d] %-8d %s", r.StatusCode, r.Size, r.URL)
	if r.Redirect != "" {
		line += " -> " + r.Redirect
	}
	_, err := fmt.Fprintln(w.f, line)
	return err
}
func (w *plainWriter) Close() error { return w.f.Close() }

type jsonlWriter struct {
	f  *os.File
	mu sync.Mutex
}

func NewJSONL(path string) (Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &jsonlWriter{f: f}, nil
}

func (w *jsonlWriter) Write(r Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	enc := json.NewEncoder(w.f)
	return enc.Encode(r)
}
func (w *jsonlWriter) Close() error { return w.f.Close() }

type csvWriter struct {
	f   *os.File
	w   *csv.Writer
	mu  sync.Mutex
	hdr bool
}

func NewCSV(path string) (Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := csv.NewWriter(f)
	w.Write([]string{"url", "status", "size", "redirect", "content_type", "words", "lines", "duration_ms", "timestamp"})
	w.Flush()
	return &csvWriter{f: f, w: w, hdr: true}, nil
}

func (w *csvWriter) Write(r Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	err := w.w.Write([]string{
		r.URL,
		fmt.Sprintf("%d", r.StatusCode),
		fmt.Sprintf("%d", r.Size),
		r.Redirect,
		r.ContentType,
		fmt.Sprintf("%d", r.Words),
		fmt.Sprintf("%d", r.Lines),
		fmt.Sprintf("%d", r.Duration),
		r.Timestamp.Format(time.RFC3339),
	})
	w.w.Flush()
	return err
}
func (w *csvWriter) Close() error { w.w.Flush(); return w.f.Close() }

func escapeHTML(s string) string {
	return html.EscapeString(s)
}

func escapeMarkdownCell(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

type htmlWriter struct {
	f      *os.File
	mu     sync.Mutex
	count  int
	target string
}

func NewHTML(path, target string) (Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	safeTarget := escapeHTML(target)
	fmt.Fprintf(f, `<!doctype html><html><head><meta charset="utf-8">
<title>godirsearch - %s</title>
<style>
body{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:24px}
h1{border-bottom:1px solid #30363d;padding-bottom:12px}
.meta{color:#8b949e;font-size:14px;margin-bottom:24px}
table{border-collapse:collapse;width:100%%}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #21262d;font-size:14px}
th{background:#161b22;position:sticky;top:0}
tr:hover{background:#161b22}
.s2xx{color:#3fb950}.s3xx{color:#58a6ff}.s4xx{color:#d29922}.s5xx{color:#f85149}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
.size{color:#8b949e;font-family:monospace}
</style></head><body>
<h1>godirsearch report</h1>
<div class="meta">Target: <code>%s</code> &bull; Generated: %s</div>
<table><thead><tr><th>Status</th><th>Size</th><th>URL</th><th>Redirect</th><th>Content-Type</th></tr></thead><tbody>
`, safeTarget, safeTarget, time.Now().Format(time.RFC3339))
	return &htmlWriter{f: f, target: target}, nil
}

func (w *htmlWriter) Write(r Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	class := "s5xx"
	switch {
	case r.StatusCode < 300:
		class = "s2xx"
	case r.StatusCode < 400:
		class = "s3xx"
	case r.StatusCode < 500:
		class = "s4xx"
	}
	safeURL := escapeHTML(r.URL)
	safeRedirect := escapeHTML(r.Redirect)
	safeContentType := escapeHTML(r.ContentType)

	_, err := fmt.Fprintf(w.f,
		`<tr><td class="%s">%d</td><td class="size">%d</td><td><a href="%s" target="_blank" rel="noopener">%s</a></td><td>%s</td><td>%s</td></tr>`+"\n",
		class, r.StatusCode, r.Size, safeURL, safeURL, safeRedirect, safeContentType)
	w.count++
	return err
}

func (w *htmlWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Fprintf(w.f, "</tbody></table><div class=\"meta\" style=\"margin-top:16px\">Results: %d</div></body></html>\n", w.count)
	return w.f.Close()
}

func writeHTML(w io.Writer, target string, results []Result) {}

// ============ Markdown writer ============
type mdWriter struct {
	f      *os.File
	hdr    bool
	mu     sync.Mutex
	target string
}

func NewMarkdown(path, target string) (Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(f, "# godirsearch report\n\n**Target**: `%s`  \n**Generated**: %s\n\n| Status | Size | URL | Redirect |\n|--------|------|-----|----------|\n",
		escapeMarkdownCell(target), time.Now().Format(time.RFC3339))
	return &mdWriter{f: f, hdr: true, target: target}, nil
}

func (w *mdWriter) Write(r Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := fmt.Fprintf(w.f, "| %d | %d | `%s` | %s |\n",
		r.StatusCode, r.Size, escapeMarkdownCell(r.URL), escapeMarkdownCell(r.Redirect))
	return err
}
func (w *mdWriter) Close() error { return w.f.Close() }
