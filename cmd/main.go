package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"godirsearch/internal/filter"
	"godirsearch/internal/output"
	"godirsearch/internal/scanner"
	"godirsearch/internal/wordlist"
)

const version = "0.2.0"

// ANSI colors
const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cPurple = "\033[35m"
	cCyan   = "\033[36m"
	cGray   = "\033[90m"
)
var defaultUAPool = []string{
	"godirsearch/" + version + " (web path scanner)",
}

func statusColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return cGreen
	case code >= 300 && code < 400:
		return cCyan
	case code >= 400 && code < 500:
		return cYellow
	case code >= 500:
		return cRed
	}
	return cGray
}

func banner() {
	fmt.Fprintf(os.Stderr, `%s%s
  ┌─────────────────────────────────────────┐
  │  godirsearch v%s                     │
  │  concurrent web path scanner            │
  │  https://github.com/AnggaTechI          │
  └─────────────────────────────────────────┘%s
`, cBold, cCyan, version, cReset)
}

func main() {
	var (
		targetURL  = flag.String("u", "", "Target URL (ex: https://example.com)")
		targetList = flag.String("l", "", "File berisi list target URL")
		cidr       = flag.String("cidr", "", "CIDR range (ex: 10.0.0.0/24) - akan di-probe per IP")
		scheme     = flag.String("scheme", "https", "Default scheme untuk URL tanpa scheme")

		wordlistPath  = flag.String("w", "", "Wordlist file(s), comma-separated")
		extensions    = flag.String("e", "", "Ekstensi, comma-separated (ex: php,html,js)")
		excludeExts   = flag.String("X", "", "Ekstensi yang di-exclude")
		forceExts     = flag.Bool("f", false, "Append ekstensi ke SEMUA entry (SecLists-style)")
		overwriteExts = flag.Bool("O", false, "Overwrite ekstensi yang udah ada di wordlist entry")
		prefixes      = flag.String("prefixes", "", "Prefix untuk tiap entry, comma-separated")
		suffixes      = flag.String("suffixes", "", "Suffix untuk tiap entry, comma-separated")
		lowercase     = flag.Bool("lowercase", false, "Lowercase transform")
		uppercase     = flag.Bool("uppercase", false, "Uppercase transform")
		capitalize    = flag.Bool("capitalize", false, "Capitalize transform")
		blacklistPath = flag.String("blacklist", "", "File path yang di-exclude dari wordlist")
		backupPattern = flag.Bool("backup-patterns", false, "Generate backup file patterns (.bak, ~, .swp, dll)")

		threads    = flag.Int("t", 20, "Concurrent threads")
		timeout    = flag.Int("timeout", 10, "Request timeout (detik)")
		maxRate    = flag.Int("max-rate", 30, "Max requests per detik (0 = unlimited, default 30 untuk menghormati target)")
		delay      = flag.Float64("delay", 0, "Delay antar request (detik)")
		retries    = flag.Int("retries", 1, "Jumlah retry saat error")
		maxRuntime = flag.Int("max-time", 0, "Max total runtime detik (0 = unlimited)")
		exitErr    = flag.Bool("exit-on-error", false, "Stop scan saat ketemu error connection")

		method       = flag.String("method", "GET", "HTTP method (GET, HEAD, POST, ...)")
		userAgent    = flag.String("ua", "", "Custom User-Agent (override pool)")
		randomUA     = flag.Bool("random-agents", false, "Rotasi User-Agent dari pool (butuh --agents-file untuk isi pool)")
		uaFile       = flag.String("agents-file", "", "File berisi UA pool custom")
		headers      = flag.String("H", "", "Custom headers, format 'Key: Value', pisah dengan ';;'")
		cookie       = flag.String("c", "", "Cookie header")
		body         = flag.String("d", "", "Request body (untuk POST/PUT)")
		followRedir  = flag.Bool("r", false, "Follow redirects")
		maxRedirects = flag.Int("max-redirects", 5, "Max redirect hops saat follow")

		includeStatus  = flag.String("s", "", "Include status (ex: 200,301-399,401) - kalau kosong, include semua lolos filter lain")
		excludeStatus  = flag.String("es", "404,403", "Exclude status")
		excludeSizes   = flag.String("exclude-size", "", "Exclude response size (ex: 0,1234,1kb-10kb)")
		excludeText    = flag.String("exclude-text", "", "Drop response yang body-nya contain string ini (multi: pisah dengan ';;')")
		excludeRegex   = flag.String("exclude-regex", "", "Drop response yang body match regex ini")
		excludeRedir   = flag.String("exclude-redirect", "", "Drop response yang redirect ke pattern ini (regex)")
		skipOnStatus   = flag.String("skip-on-status", "", "Abort scan saat ketemu status ini (ex: 429)")
		wildcardProbes = flag.Int("wildcard-probes", 3, "Jumlah random path probe untuk wildcard detection (0 = disable)")
		bodyReadBytes  = flag.Int("body-read", 16384, "Max byte body yang dibaca per response untuk fingerprint/filter (default 16384)")

		recursive      = flag.Bool("R", false, "Recursive scan (follow found directories)")
		maxDepth       = flag.Int("max-depth", 3, "Max recursion depth")
		recursionStat  = flag.String("recursion-status", "200,301,302,403", "Status code yang trigger recursion")
		forceRecursive = flag.Bool("force-recursive", false, "Recurse ke semua found (bukan cuma directory)")
		subdirs        = flag.String("subdirs", "", "Scan dengan prefix sub-directory (ex: /api,/admin)")

		outPlain = flag.String("o", "", "Output plain text")
		outJSONL = flag.String("oj", "", "Output JSON Lines")
		outCSV   = flag.String("oc", "", "Output CSV")
		outHTML  = flag.String("oh", "", "Output HTML report")
		outMD    = flag.String("om", "", "Output Markdown")

		proxy     = flag.String("proxy", "", "HTTP/SOCKS proxy (ex: http://127.0.0.1:8080)")
		proxyList = flag.String("proxy-list", "", "File berisi list proxy untuk rotasi")

		showVer = flag.Bool("version", false, "Print version")
		quiet   = flag.Bool("q", false, "Quiet mode (hanya hasil)")
		http2   = flag.Bool("http2", true, "Enable HTTP/2 (default true)")
		tlsOK   = flag.Bool("tls-verify", false, "Verify TLS certs (default false biar bisa scan self-signed)")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("godirsearch v%s\n", version)
		return
	}

	if !*quiet {
		banner()
	}

	var targets []string
	if *targetURL != "" {
		targets = append(targets, normalizeURL(*targetURL, *scheme))
	}
	if *targetList != "" {
		lines, err := readLines(*targetList)
		if err != nil {
			fatal("gagal baca target list: %v", err)
		}
		for _, l := range lines {
			targets = append(targets, normalizeURL(l, *scheme))
		}
	}
	if *cidr != "" {
		ips, err := filter.ExpandCIDR(*cidr)
		if err != nil {
			fatal("CIDR error: %v", err)
		}
		for _, ip := range ips {
			targets = append(targets, *scheme+"://"+ip)
		}
	}

	if len(targets) == 0 {
		fatal("minimal harus ada -u, -l, atau --cidr")
	}
	if *wordlistPath == "" {
		fatal("wordlist wajib (-w)")
	}

	wlPaths := strings.Split(*wordlistPath, ",")
	words, err := wordlist.Load(wlPaths)
	if err != nil {
		fatal("gagal load wordlist: %v", err)
	}

	blacklist, err := wordlist.ParseBlacklist(*blacklistPath)
	if err != nil {
		fatal("gagal load blacklist: %v", err)
	}

	wlOpt := &wordlist.Options{
		Extensions:        splitComma(*extensions),
		ExcludeExtensions: splitComma(*excludeExts),
		ForceExtensions:   *forceExts,
		OverwriteExt:      *overwriteExts,
		Prefixes:          splitComma(*prefixes),
		Suffixes:          splitComma(*suffixes),
		Lowercase:         *lowercase,
		Uppercase:         *uppercase,
		Capitalization:    *capitalize,
		Blacklist:         blacklist,
		BackupPatterns:    *backupPattern,
	}
	paths := wordlist.Expand(words, wlOpt)

	inc, err := filter.ParseStatusRanges(*includeStatus)
	if err != nil {
		fatal("%v", err)
	}
	exc, err := filter.ParseStatusRanges(*excludeStatus)
	if err != nil {
		fatal("%v", err)
	}
	excSize, err := filter.ParseSizeRanges(*excludeSizes)
	if err != nil {
		fatal("%v", err)
	}
	skipStat, err := filter.ParseIntList(*skipOnStatus)
	if err != nil {
		fatal("%v", err)
	}

	f := &filter.Filter{
		IncludeStatus:         inc,
		ExcludeStatus:         exc,
		ExcludeSize:           excSize,
		SkipOnStatus:          skipStat,
		WildcardHashes:        make(map[uint64]bool),
		WildcardSizesByStatus: make(map[int]map[int64]bool),
	}
	if *excludeText != "" {
		f.ExcludeText = strings.Split(*excludeText, ";;")
	}
	if *excludeRegex != "" {
		re, err := regexp.Compile(*excludeRegex)
		if err != nil {
			fatal("regex error: %v", err)
		}
		f.ExcludeRegex = []*regexp.Regexp{re}
	}
	if *excludeRedir != "" {
		re, err := regexp.Compile(*excludeRedir)
		if err != nil {
			fatal("redirect regex error: %v", err)
		}
		f.ExcludeRedirect = []*regexp.Regexp{re}
	}

	var writers []output.Writer
	if *outPlain != "" {
		w, err := output.NewPlain(*outPlain)
		if err != nil {
			fatal("output error: %v", err)
		}
		writers = append(writers, w)
	}
	if *outJSONL != "" {
		w, err := output.NewJSONL(*outJSONL)
		if err != nil {
			fatal("output error: %v", err)
		}
		writers = append(writers, w)
	}
	if *outCSV != "" {
		w, err := output.NewCSV(*outCSV)
		if err != nil {
			fatal("output error: %v", err)
		}
		writers = append(writers, w)
	}
	if *outHTML != "" {
		w, err := output.NewHTML(*outHTML, targets[0])
		if err != nil {
			fatal("output error: %v", err)
		}
		writers = append(writers, w)
	}
	if *outMD != "" {
		w, err := output.NewMarkdown(*outMD, targets[0])
		if err != nil {
			fatal("output error: %v", err)
		}
		writers = append(writers, w)
	}
	if len(writers) == 0 {
		writers = append(writers, nullWriter{})
	}
	multi := output.NewMulti(writers...)
	defer multi.Close()

	uaPool := buildUAPool(*userAgent, *randomUA, *uaFile)

	var proxies []string
	if *proxyList != "" {
		lines, err := readLines(*proxyList)
		if err != nil {
			fatal("gagal baca proxy list: %v", err)
		}
		proxies = lines
	}

	recursionStatusInts, err := filter.ParseIntList(*recursionStat)
	if err != nil {
		fatal("recursion-status error: %v", err)
	}

	cfg := &scanner.Config{
		Targets:         targets,
		Paths:           paths,
		Method:          strings.ToUpper(*method),
		UserAgents:      uaPool,
		Headers:         parseHeaders(*headers),
		Cookie:          *cookie,
		Body:            *body,
		FollowRedirect:  *followRedir,
		MaxRedirects:    *maxRedirects,
		Threads:         *threads,
		Timeout:         time.Duration(*timeout) * time.Second,
		MaxRate:         *maxRate,
		Delay:           time.Duration(*delay*1000) * time.Millisecond,
		Retries:         *retries,
		MaxRuntime:      time.Duration(*maxRuntime) * time.Second,
		ExitOnError:     *exitErr,
		Recursive:       *recursive,
		ForceRecursive:  *forceRecursive,
		MaxDepth:        *maxDepth,
		RecursionStatus: recursionStatusInts,
		Proxy:           *proxy,
		ProxyList:       proxies,
		HTTP2:           *http2,
		TLSVerify:       *tlsOK,
		Subdirs:         splitComma(*subdirs),
		WildcardProbes:  *wildcardProbes,
		BodyReadBytes:   *bodyReadBytes,
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "%s[i]%s Targets      : %d\n", cBlue, cReset, len(targets))
		fmt.Fprintf(os.Stderr, "%s[i]%s Wordlist     : %d entries → %d paths (setelah ekspansi)\n", cBlue, cReset, len(words), len(paths))
		fmt.Fprintf(os.Stderr, "%s[i]%s Threads      : %d | Timeout: %ds | Rate: %s\n",
			cBlue, cReset, cfg.Threads, *timeout, rateStr(*maxRate))
		ext := splitComma(*extensions)
		if len(ext) > 0 {
			fmt.Fprintf(os.Stderr, "%s[i]%s Extensions   : %s (force=%v, overwrite=%v)\n",
				cBlue, cReset, strings.Join(ext, ","), *forceExts, *overwriteExts)
		}
		fmt.Fprintf(os.Stderr, "%s[i]%s Method       : %s | HTTP/2: %v | TLS verify: %v\n",
			cBlue, cReset, cfg.Method, *http2, *tlsOK)
		fmt.Fprintf(os.Stderr, "%s[i]%s Body sample  : %d bytes/request\n", cBlue, cReset, cfg.BodyReadBytes)
		if len(proxies) > 0 || *proxy != "" {
			n := len(proxies)
			if n == 0 {
				n = 1
			}
			fmt.Fprintf(os.Stderr, "%s[i]%s Proxies      : %d\n", cBlue, cReset, n)
		}
		fmt.Fprintf(os.Stderr, "%s[i]%s Output       : %s\n\n", cBlue, cReset, outputDesc(*outPlain, *outJSONL, *outCSV, *outHTML, *outMD))
	}

	s, err := scanner.New(cfg, f, multi)
	if err != nil {
		fatal("scanner init error: %v", err)
	}

	s.OnResult = func(r output.Result) {
		if *quiet {
			fmt.Printf("[%d] %-8d %s\n", r.StatusCode, r.Size, r.URL)
			return
		}
		fmt.Fprintf(os.Stderr, "\r\033[K") 
		col := statusColor(r.StatusCode)
		line := fmt.Sprintf("%s[%d]%s %s%-10d%s %s", col, r.StatusCode, cReset, cDim, r.Size, cReset, r.URL)
		if r.Redirect != "" {
			line += fmt.Sprintf(" %s→ %s%s", cCyan, r.Redirect, cReset)
		}
		fmt.Println(line)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\n[!] Interrupt diterima, shutting down gracefully...")
		s.Stop()
		select {
		case <-sigCh:
			fmt.Fprintln(os.Stderr, "[!] Force exit")
			os.Exit(130)
		case <-time.After(5 * time.Second):
			fmt.Fprintln(os.Stderr, "[!] Shutdown timeout, force exit")
			os.Exit(130)
		}
	}()

	if !*quiet {
		go progressReporter(s)
	}

	if err := s.Run(); err != nil {
		fatal("scan error: %v", err)
	}

	stats := s.Stats()
	fmt.Fprintf(os.Stderr, "\r\033[K")
	if !*quiet {
		fmt.Fprintf(os.Stderr, "\n%s[✓]%s Selesai dalam %s\n", cGreen, cReset, stats.Elapsed.Round(time.Millisecond))
		fmt.Fprintf(os.Stderr, "    %sProcessed%s  : %d\n", cDim, cReset, stats.Processed)
		fmt.Fprintf(os.Stderr, "    %sFound%s      : %d\n", cDim, cReset, stats.Found)
		fmt.Fprintf(os.Stderr, "    %sErrors%s     : %d\n", cDim, cReset, stats.Errors)
		fmt.Fprintf(os.Stderr, "    %sAvg rate%s   : %.1f req/s\n", cDim, cReset, stats.Rate)
		fmt.Fprintf(os.Stderr, "    %sBytes read%s : %s\n", cDim, cReset, humanBytes(stats.BytesRead))
		if stats.Throttled > 0 {
			fmt.Fprintf(os.Stderr, "    %sThrottled%s  : %d times (target rate-limited)\n", cDim, cReset, stats.Throttled)
		}
	}
}

func progressReporter(s *scanner.Scanner) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		st := s.Stats()
		pct := 0.0
		if st.Total > 0 {
			pct = float64(st.Processed) / float64(st.Total) * 100
		}
		fmt.Fprintf(os.Stderr, "\r%s[*]%s %d/%d (%.1f%%) | %.0f r/s | found: %d | err: %d    ",
			cBlue, cReset, st.Processed, st.Total, pct, st.Rate, st.Found, st.Errors)
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

func normalizeURL(raw, scheme string) string {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = scheme + "://" + raw
	}
	return raw
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseHeaders(s string) map[string]string {
	out := make(map[string]string)
	if s == "" {
		return out
	}
	for _, part := range strings.Split(s, ";;") {
		i := strings.Index(part, ":")
		if i < 0 {
			continue
		}
		k := strings.TrimSpace(part[:i])
		v := strings.TrimSpace(part[i+1:])
		if k != "" {
			out[k] = v
		}
	}
	return out
}

func buildUAPool(single string, random bool, file string) []string {
	if single != "" {
		return []string{single}
	}
	if file != "" {
		if lines, err := readLines(file); err == nil && len(lines) > 0 {
			return lines
		}
	}
	if random {
		return defaultUAPool
	}
	return []string{defaultUAPool[0]}
}

func rateStr(r int) string {
	if r <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d req/s (adaptive)", r)
}

func outputDesc(plain, jsonl, csvP, html, md string) string {
	var parts []string
	if plain != "" {
		parts = append(parts, "plain="+filepath.Base(plain))
	}
	if jsonl != "" {
		parts = append(parts, "jsonl="+filepath.Base(jsonl))
	}
	if csvP != "" {
		parts = append(parts, "csv="+filepath.Base(csvP))
	}
	if html != "" {
		parts = append(parts, "html="+filepath.Base(html))
	}
	if md != "" {
		parts = append(parts, "md="+filepath.Base(md))
	}
	if len(parts) == 0 {
		return "(stdout only)"
	}
	return strings.Join(parts, ", ")
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s[!]%s "+format+"\n", append([]interface{}{cRed, cReset}, args...)...)
	os.Exit(1)
}

type nullWriter struct{}

func (nullWriter) Write(output.Result) error { return nil }
func (nullWriter) Close() error              { return nil }

var _ = io.Discard
