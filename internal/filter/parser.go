package filter

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func ParseStatusRanges(s string) ([]StatusRange, error) {
	if s == "" {
		return nil, nil
	}
	var out []StatusRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bits := strings.SplitN(part, "-", 2)
			from, err1 := strconv.Atoi(strings.TrimSpace(bits[0]))
			to, err2 := strconv.Atoi(strings.TrimSpace(bits[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("status range tidak valid: %q", part)
			}
			out = append(out, StatusRange{From: from, To: to})
		} else {
			code, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("status code tidak valid: %q", part)
			}
			out = append(out, StatusRange{From: code, To: code})
		}
	}
	return out, nil
}

func ParseSizeRanges(s string) ([]SizeRange, error) {
	if s == "" {
		return nil, nil
	}
	var out []SizeRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bits := strings.SplitN(part, "-", 2)
			from, err1 := parseSize(bits[0])
			to, err2 := parseSize(bits[1])
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("size range tidak valid: %q", part)
			}
			out = append(out, SizeRange{From: from, To: to})
		} else {
			sz, err := parseSize(part)
			if err != nil {
				return nil, err
			}
			out = append(out, SizeRange{From: sz, To: sz})
		}
	}
	return out, nil
}

func parseSize(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "gb"):
		mult = 1 << 30
		s = strings.TrimSuffix(s, "gb")
	case strings.HasSuffix(s, "mb"):
		mult = 1 << 20
		s = strings.TrimSuffix(s, "mb")
	case strings.HasSuffix(s, "kb"):
		mult = 1 << 10
		s = strings.TrimSuffix(s, "kb")
	case strings.HasSuffix(s, "b"):
		s = strings.TrimSuffix(s, "b")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, err
	}
	return n * mult, nil
}

func ParseIntList(s string) ([]int, error) {
	if s == "" {
		return nil, nil
	}
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("integer tidak valid: %q", part)
		}
		out = append(out, n)
	}
	return out, nil
}

func ExpandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
		if len(ips) > 65536 {
			return nil, fmt.Errorf("CIDR terlalu besar (>65536 host)")
		}
	}
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}
