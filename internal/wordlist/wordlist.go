package wordlist

import (
	"bufio"
	"os"
	"strings"
)

const (
	KwExt     = "%EXT%"    
	KwNoForce = "%NOFORCE%"
)

var protectedExtensions = map[string]bool{
	"log": true, "json": true, "xml": true, "yaml": true, "yml": true,
	"md": true, "txt": true, "csv": true, "pdf": true,
	"jpg": true, "jpeg": true, "png": true, "gif": true, "svg": true,
	"webp": true, "ico": true, "mp3": true, "mp4": true, "webm": true,
	"woff": true, "woff2": true, "ttf": true, "eot": true,
	"zip": true, "tar": true, "gz": true, "7z": true, "rar": true,
}

type Options struct {
	Extensions        []string 
	ExcludeExtensions []string 
	ForceExtensions   bool     
	OverwriteExt      bool    
	Prefixes          []string 
	Suffixes          []string 
	Lowercase         bool
	Uppercase         bool
	Capitalization    bool
	Blacklist         map[string]bool 

	BackupPatterns bool
}

var backupSuffixes = []string{
	".bak", ".old", ".backup", ".orig", ".save", ".swp", ".swo",
	".tmp", "~", ".1", ".2", ".copy",
}
var backupPrefixes = []string{".", "_", "#"}

func Load(paths []string) ([]string, error) {
	seen := make(map[string]bool)
	var result []string

	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !seen[line] {
				seen[line] = true
				result = append(result, line)
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func Expand(words []string, opt *Options) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		if s == "" {
			return
		}
		if opt.Blacklist[s] {
			return
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}

	exts := normalizeExts(opt.Extensions)
	excludeExts := normalizeExts(opt.ExcludeExtensions)

	for _, raw := range words {
		if hasExcludedExt(raw, excludeExts) {
			continue
		}

		bases := applyCase(raw, opt)

		for _, base := range bases {
			for _, variant := range expandOne(base, exts, opt) {
				add(variant)
				for _, pref := range opt.Prefixes {
					add(pref + variant)
				}
				for _, suf := range opt.Suffixes {
					add(variant + suf)
				}

				if opt.BackupPatterns {
					for _, bs := range backupSuffixes {
						add(variant + bs)
					}
					if len(variant) <= 20 && !strings.Contains(variant, "/") {
						for _, bp := range backupPrefixes {
							add(bp + variant)
						}
					}
				}
			}
		}
	}
	return out
}

func expandOne(entry string, exts []string, opt *Options) []string {
	if strings.Contains(entry, KwExt) {
		if len(exts) == 0 {
			return nil
		}
		var r []string
		for _, e := range exts {
			r = append(r, strings.ReplaceAll(entry, KwExt, e))
		}
		return r
	}

	noForce := strings.Contains(entry, KwNoForce)
	clean := strings.ReplaceAll(entry, KwNoForce, "")

	if !opt.ForceExtensions || noForce || len(exts) == 0 {
		return []string{clean}
	}

	if opt.OverwriteExt {
		if ext := getExt(clean); ext != "" && !protectedExtensions[ext] {
			stem := strings.TrimSuffix(clean, "."+ext)
			r := []string{clean}
			for _, e := range exts {
				if e != ext {
					r = append(r, stem+"."+e)
				}
			}
			return r
		}
	}

	out := []string{clean, clean + "/"}
	for _, e := range exts {
		out = append(out, clean+"."+e)
	}
	return out
}

func applyCase(s string, opt *Options) []string {
	var r []string
	r = append(r, s)
	if opt.Lowercase {
		r = append(r, strings.ToLower(s))
	}
	if opt.Uppercase {
		r = append(r, strings.ToUpper(s))
	}
	if opt.Capitalization && len(s) > 0 {
		r = append(r, strings.ToUpper(s[:1])+s[1:])
	}
	// dedupe sederhana
	seen := make(map[string]bool)
	var out []string
	for _, x := range r {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func normalizeExts(in []string) []string {
	var out []string
	for _, e := range in {
		e = strings.TrimSpace(strings.TrimPrefix(e, "."))
		if e != "" {
			out = append(out, e)
		}
	}
	return out
}

func hasExcludedExt(s string, excl []string) bool {
	ext := getExt(s)
	if ext == "" {
		return false
	}
	for _, e := range excl {
		if strings.EqualFold(ext, e) {
			return true
		}
	}
	return false
}

func getExt(s string) string {
	// hanya ambil ekstensi dari segment terakhir
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, "."); i > 0 {
		return strings.ToLower(s[i+1:])
	}
	return ""
}

func ParseBlacklist(path string) (map[string]bool, error) {
	out := make(map[string]bool)
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out[line] = true
		}
	}
	return out, sc.Err()
}
