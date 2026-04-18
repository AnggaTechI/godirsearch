# 🚀 godirsearch

<p align="center">
  <b>Concurrent web path scanner written in Go</b><br>
  wildcard-aware • adaptive • recursive • multi-output
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-Scanner-00ADD8?style=for-the-badge&logo=go&logoColor=white" />
  <img src="https://img.shields.io/badge/Status-Active-2ea043?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Version-0.2.0-1f6feb?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Output-Plain%20%7C%20JSONL%20%7C%20CSV%20%7C%20HTML%20%7C%20Markdown-8250df?style=for-the-badge" />
</p>

---

## 📌 Overview

**godirsearch** is a fast and flexible Go-based web path scanner built for authorized reconnaissance and endpoint discovery.
It supports **single targets, target lists, and CIDR ranges**, while also providing **wildcard detection, adaptive rate limiting, recursive scanning, proxy support, custom headers, rotating user-agents, and multiple report formats**.

Built to stay lightweight, clean, and practical for real-world scanning workflows.

---

## ✨ Features

- ⚡ **Concurrent scanning** with configurable threads
- 🎯 **Multiple target modes**: single URL, file list, or CIDR range
- 🧠 **Wildcard-aware detection** to reduce false positives
- 🔁 **Recursive scan mode** with configurable depth
- 🛡️ **Adaptive rate limiter** that reacts to `429` and `503`
- 🌐 **HTTP/2 support** and optional TLS verification
- 🍪 **Custom headers, cookies, body, and method support**
- 🕵️ **User-Agent rotation** with file-based pools
- 🔌 **Single proxy or rotating proxy list**
- 🧩 **Wordlist expansion** with extensions, prefixes, suffixes, blacklist, and backup patterns
- 📊 **Filtering system** for status, size, body content, regex, and redirect targets
- 📝 **Export results** to plain text, JSONL, CSV, HTML, or Markdown
- ⏱️ **Graceful shutdown** with progress stats

---

## 🧱 Project Structure

```bash
.
├── cmd/
│   ├── a.txt
│   └── main.go
├── internal/
│   ├── filter/
│   │   ├── filter.go
│   │   └── parser.go
│   ├── output/
│   │   └── writer.go
│   ├── scanner/
│   │   ├── config.go
│   │   ├── ratelimit.go
│   │   ├── scanner.go
│   │   └── wildcard.go
│   └── wordlist/
│       └── wordlist.go
├── wordlists/
│   └── common.txt
├── common.txt
└── go.mod
```

---

## ⚙️ Installation

### Clone repository

```bash
git clone https://github.com/AnggaTechI/godirsearch.git
cd godirsearch
```

### Build binary

```bash
go build -o godirsearch ./cmd
```

### Run version check

```bash
./godirsearch --version
```

---

## ▶️ Basic Usage

### Scan a single target

```bash
./godirsearch -u https://example.com -w wordlists/common.txt
```

### Scan with extensions

```bash
./godirsearch -u https://example.com -w wordlists/common.txt -e php,html,js -f
```

### Scan target list

```bash
./godirsearch -l targets.txt -w wordlists/common.txt -t 50
```

### Scan CIDR range

```bash
./godirsearch --cidr 10.0.0.0/24 --scheme https -w wordlists/common.txt
```

### Recursive scan

```bash
./godirsearch -u https://example.com -w wordlists/common.txt -R --max-depth 3
```

### Save reports in multiple formats

```bash
./godirsearch -u https://example.com -w wordlists/common.txt \
  -o results.txt -oj results.jsonl -oc results.csv -oh results.html -om results.md
```

---

## 🧪 Example Commands

### Custom headers and cookies

```bash
./godirsearch -u https://example.com -w wordlists/common.txt \
  -H "Authorization: Bearer TOKEN;;X-Test: 1" \
  -c "session=abc123"
```

### POST request with body

```bash
./godirsearch -u https://example.com/api -w wordlists/common.txt \
  --method POST -d '{"ping":"1"}'
```

### Proxy rotation

```bash
./godirsearch -u https://example.com -w wordlists/common.txt --proxy-list proxies.txt
```

### Rotating user-agents

```bash
./godirsearch -u https://example.com -w wordlists/common.txt --random-agents --agents-file agents.txt
```

### Follow redirects

```bash
./godirsearch -u https://example.com -w wordlists/common.txt -r --max-redirects 5
```

### Quiet mode

```bash
./godirsearch -u https://example.com -w wordlists/common.txt -q
```

---

## 🎛️ Useful Flags

| Flag | Description |
|------|-------------|
| `-u` | Single target URL |
| `-l` | File containing target URLs |
| `--cidr` | CIDR range input |
| `--scheme` | Default scheme for targets without scheme |
| `-w` | Wordlist file(s), comma-separated |
| `-e` | File extensions |
| `-f` | Force extensions on all entries |
| `-O` | Overwrite existing extension |
| `--prefixes` | Prefix for each entry |
| `--suffixes` | Suffix for each entry |
| `--backup-patterns` | Generate backup-style filenames |
| `-t` | Concurrent threads |
| `--timeout` | Request timeout in seconds |
| `--max-rate` | Max requests per second |
| `--delay` | Delay between requests |
| `--retries` | Retry count |
| `--max-time` | Max runtime |
| `--method` | HTTP method |
| `--ua` | Custom user-agent |
| `--random-agents` | Rotate user-agents |
| `--agents-file` | File containing user-agent pool |
| `-H` | Custom headers |
| `-c` | Cookie header |
| `-d` | Request body |
| `-r` | Follow redirects |
| `-s` | Include status codes |
| `--es` | Exclude status codes |
| `--exclude-size` | Exclude by response size |
| `--exclude-text` | Exclude body containing text |
| `--exclude-regex` | Exclude body matching regex |
| `--exclude-redirect` | Exclude redirect target by regex |
| `--skip-on-status` | Abort scan on certain status |
| `-R` | Enable recursive scan |
| `--max-depth` | Maximum recursion depth |
| `--recursion-status` | Status codes that trigger recursion |
| `--force-recursive` | Recurse on all findings |
| `--subdirs` | Start scanning from subdirectories |
| `-o` | Plain text output |
| `-oj` | JSONL output |
| `-oc` | CSV output |
| `-oh` | HTML report |
| `-om` | Markdown output |
| `--proxy` | Single proxy |
| `--proxy-list` | Rotating proxy list |
| `--http2` | Enable HTTP/2 |
| `--tls-verify` | Verify TLS certificate |
| `-q` | Quiet mode |
| `--version` | Print version |

---

## 🧠 How It Works

`godirsearch` loads one or more wordlists, expands entries using the selected options, then distributes generated paths across concurrent workers.
Each worker sends requests using the configured HTTP settings, applies filters, and writes valid results into one or more output writers.

Before scanning starts, the tool can run **wildcard probes** using random paths to fingerprint generic target responses.
This helps reduce noisy matches using **body hashing** and **status-size fingerprints**.

When the server starts rate-limiting with `429` or `503`, the adaptive limiter reduces request speed automatically.
When recursion is enabled, newly discovered directory-like endpoints can be fed back into the queue until the depth limit is reached.

---

## 📤 Output Formats

Supported outputs:

- **Plain text**
- **JSONL**
- **CSV**
- **HTML report**
- **Markdown report**

Example:

```bash
./godirsearch -u https://example.com -w wordlists/common.txt -oj out.jsonl -oh report.html
```

---

## 🖥️ Sample Output

```bash
[200] 512      https://example.com/admin
[301] 0        https://example.com/login -> https://example.com/login/
[403] 128      https://example.com/private
```

---

## 📋 Notes

- Use this tool only on systems you own or are explicitly authorized to assess.
- Default rate limiting is intentionally conservative.
- TLS verification is optional, useful for self-signed targets.
- Wildcard detection can be tuned or disabled with `--wildcard-probes`.

---

## 👤 Author

**AnggaTechI**  
GitHub: https://github.com/AnggaTechI

---

## ⭐ Support

If this project helps you, consider giving it a star on GitHub.
