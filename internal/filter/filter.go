package filter

import (
	"regexp"
	"strings"
	"sync"
)

type Filter struct {
	IncludeStatus []StatusRange
	IncludeSize   []SizeRange
	ExcludeStatus   []StatusRange
	ExcludeSize     []SizeRange
	ExcludeText     []string
	ExcludeRegex    []*regexp.Regexp
	ExcludeRedirect []*regexp.Regexp

	SkipOnStatus []int

	wildcardMu            sync.RWMutex
	WildcardHashes        map[uint64]bool
	WildcardSizesByStatus map[int]map[int64]bool
}

type StatusRange struct {
	From, To int
}

func (r StatusRange) Contains(code int) bool {
	return code >= r.From && code <= r.To
}

type SizeRange struct {
	From, To int64
}

func (r SizeRange) Contains(size int64) bool {
	return size >= r.From && size <= r.To
}

type ResponseInfo struct {
	StatusCode int
	Size       int64
	Body       []byte 
	Redirect   string
	BodyHash   uint64 
}

type Action int

const (
	ActionReport Action = iota 
	ActionDrop                
	ActionAbort               
)

func (f *Filter) MergeWildcard(hashes map[uint64]bool, sizesByStatus map[int]map[int64]bool) {
	f.wildcardMu.Lock()
	defer f.wildcardMu.Unlock()

	if f.WildcardHashes == nil {
		f.WildcardHashes = make(map[uint64]bool, len(hashes))
	}
	if f.WildcardSizesByStatus == nil {
		f.WildcardSizesByStatus = make(map[int]map[int64]bool, len(sizesByStatus))
	}

	for h := range hashes {
		f.WildcardHashes[h] = true
	}
	for code, sizes := range sizesByStatus {
		if f.WildcardSizesByStatus[code] == nil {
			f.WildcardSizesByStatus[code] = make(map[int64]bool, len(sizes))
		}
		for sz := range sizes {
			f.WildcardSizesByStatus[code][sz] = true
		}
	}
}

func (f *Filter) IsWildcard(statusCode int, bodyHash uint64, size int64) bool {
	f.wildcardMu.RLock()
	defer f.wildcardMu.RUnlock()

	if f.WildcardHashes[bodyHash] {
		return true
	}
	if sizes := f.WildcardSizesByStatus[statusCode]; sizes != nil && sizes[size] {
		return true
	}
	return false
}

func (f *Filter) Evaluate(r *ResponseInfo) Action {
	for _, code := range f.SkipOnStatus {
		if r.StatusCode == code {
			return ActionAbort
		}
	}

	if len(f.IncludeStatus) > 0 {
		matched := false
		for _, sr := range f.IncludeStatus {
			if sr.Contains(r.StatusCode) {
				matched = true
				break
			}
		}
		if !matched {
			return ActionDrop
		}
	}

	for _, sr := range f.ExcludeStatus {
		if sr.Contains(r.StatusCode) {
			return ActionDrop
		}
	}

	if len(f.IncludeSize) > 0 {
		matched := false
		for _, sr := range f.IncludeSize {
			if sr.Contains(r.Size) {
				matched = true
				break
			}
		}
		if !matched {
			return ActionDrop
		}
	}
	for _, sr := range f.ExcludeSize {
		if sr.Contains(r.Size) {
			return ActionDrop
		}
	}

	if f.IsWildcard(r.StatusCode, r.BodyHash, r.Size) {
		return ActionDrop
	}

	if len(r.Body) > 0 {
		bodyStr := string(r.Body)
		for _, t := range f.ExcludeText {
			if strings.Contains(bodyStr, t) {
				return ActionDrop
			}
		}
		for _, re := range f.ExcludeRegex {
			if re.Match(r.Body) {
				return ActionDrop
			}
		}
	}

	if r.Redirect != "" {
		for _, re := range f.ExcludeRedirect {
			if re.MatchString(r.Redirect) {
				return ActionDrop
			}
		}
	}

	return ActionReport
}
