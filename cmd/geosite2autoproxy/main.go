package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type domainType uint64

const (
	domainPlain domainType = iota
	domainRegex
	domainRoot
	domainFull
)

type domainRule struct {
	Type  domainType
	Value string
}

func main() {
	input := flag.String("input", "geosite.dat", "input geosite.dat")
	list := flag.String("list", "cn", "geosite list name")
	output := flag.String("output", "cn.txt", "plain AutoProxy output")
	base64Output := flag.String("base64-output", "cn.base64.txt", "base64 AutoProxy output")
	reference := flag.String("reference", "", "optional upstream plaintext list for exact validation")
	flag.Parse()

	data, err := os.ReadFile(*input)
	fatalIf(err)

	rules, err := extractGeoSite(data, *list)
	fatalIf(err)

	if *reference != "" {
		refRules, err := parseReferenceList(*reference)
		fatalIf(err)
		fatalIf(compareRuleSets(rules, refRules))
	}

	plain, err := buildAutoProxy(rules, strings.ToLower(*list))
	fatalIf(err)
	encoded := base64.StdEncoding.EncodeToString(plain)

	fatalIf(os.WriteFile(*output, plain, 0o644))
	fatalIf(os.WriteFile(*base64Output, append([]byte(encoded), '\n'), 0o644))

	counts := map[domainType]int{}
	for _, r := range rules {
		counts[r.Type]++
	}
	fmt.Printf("validated geosite:%s: total=%d root=%d full=%d regex=%d plain=%d\n",
		strings.ToLower(*list), len(rules), counts[domainRoot], counts[domainFull], counts[domainRegex], counts[domainPlain])
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// extractGeoSite parses the wire format defined by
// v2ray.core.app.router.routercommon.GeoSiteList without external protobuf dependencies.
func extractGeoSite(data []byte, target string) ([]domainRule, error) {
	var found [][]domainRule
	for len(data) > 0 {
		field, wire, n, err := consumeTag(data)
		if err != nil {
			return nil, err
		}
		data = data[n:]
		if field == 1 && wire == 2 {
			msg, consumed, err := consumeBytes(data)
			if err != nil {
				return nil, fmt.Errorf("GeoSiteList.entry: %w", err)
			}
			data = data[consumed:]
			code, rules, err := parseGeoSite(msg)
			if err != nil {
				return nil, err
			}
			if strings.EqualFold(code, target) {
				found = append(found, rules)
			}
			continue
		}
		consumed, err := skipField(data, wire)
		if err != nil {
			return nil, err
		}
		data = data[consumed:]
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("geosite list %q not found", target)
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("geosite list %q appears %d times", target, len(found))
	}
	if len(found[0]) == 0 {
		return nil, fmt.Errorf("geosite list %q is empty", target)
	}
	return found[0], nil
}

func parseGeoSite(data []byte) (string, []domainRule, error) {
	var code string
	var rules []domainRule
	for len(data) > 0 {
		field, wire, n, err := consumeTag(data)
		if err != nil {
			return "", nil, fmt.Errorf("GeoSite: %w", err)
		}
		data = data[n:]
		switch {
		case field == 1 && wire == 2:
			b, consumed, err := consumeBytes(data)
			if err != nil {
				return "", nil, fmt.Errorf("GeoSite.country_code: %w", err)
			}
			code = string(b)
			data = data[consumed:]
		case field == 2 && wire == 2:
			b, consumed, err := consumeBytes(data)
			if err != nil {
				return "", nil, fmt.Errorf("GeoSite.domain: %w", err)
			}
			rule, err := parseDomain(b)
			if err != nil {
				return "", nil, err
			}
			rules = append(rules, rule)
			data = data[consumed:]
		default:
			consumed, err := skipField(data, wire)
			if err != nil {
				return "", nil, err
			}
			data = data[consumed:]
		}
	}
	return code, rules, nil
}

func parseDomain(data []byte) (domainRule, error) {
	rule := domainRule{Type: domainPlain}
	var hasValue bool
	for len(data) > 0 {
		field, wire, n, err := consumeTag(data)
		if err != nil {
			return domainRule{}, fmt.Errorf("Domain: %w", err)
		}
		data = data[n:]
		switch {
		case field == 1 && wire == 0:
			v, consumed, err := consumeVarint(data)
			if err != nil {
				return domainRule{}, fmt.Errorf("Domain.type: %w", err)
			}
			rule.Type = domainType(v)
			data = data[consumed:]
		case field == 2 && wire == 2:
			b, consumed, err := consumeBytes(data)
			if err != nil {
				return domainRule{}, fmt.Errorf("Domain.value: %w", err)
			}
			rule.Value = string(b)
			hasValue = true
			data = data[consumed:]
		default:
			consumed, err := skipField(data, wire)
			if err != nil {
				return domainRule{}, err
			}
			data = data[consumed:]
		}
	}
	if !hasValue || rule.Value == "" {
		return domainRule{}, errors.New("Domain.value is empty")
	}
	if rule.Type > domainFull {
		return domainRule{}, fmt.Errorf("unsupported Domain.type %d for %q", rule.Type, rule.Value)
	}
	return rule, nil
}

func consumeTag(data []byte) (field uint64, wire byte, consumed int, err error) {
	v, n, err := consumeVarint(data)
	if err != nil {
		return 0, 0, 0, err
	}
	field = v >> 3
	wire = byte(v & 7)
	if field == 0 {
		return 0, 0, 0, errors.New("invalid protobuf field number 0")
	}
	return field, wire, n, nil
}

func consumeVarint(data []byte) (uint64, int, error) {
	var x uint64
	for i := 0; i < 10; i++ {
		if i >= len(data) {
			return 0, 0, errors.New("truncated varint")
		}
		b := data[i]
		if i == 9 && b > 1 {
			return 0, 0, errors.New("varint overflow")
		}
		x |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return x, i + 1, nil
		}
	}
	return 0, 0, errors.New("varint overflow")
}

func consumeBytes(data []byte) ([]byte, int, error) {
	l, n, err := consumeVarint(data)
	if err != nil {
		return nil, 0, err
	}
	if l > uint64(len(data)-n) {
		return nil, 0, errors.New("truncated length-delimited field")
	}
	end := n + int(l)
	return data[n:end], end, nil
}

func skipField(data []byte, wire byte) (int, error) {
	switch wire {
	case 0:
		_, n, err := consumeVarint(data)
		return n, err
	case 1:
		if len(data) < 8 {
			return 0, errors.New("truncated fixed64 field")
		}
		return 8, nil
	case 2:
		_, n, err := consumeBytes(data)
		return n, err
	case 5:
		if len(data) < 4 {
			return 0, errors.New("truncated fixed32 field")
		}
		return 4, nil
	default:
		return 0, fmt.Errorf("unsupported protobuf wire type %d", wire)
	}
}

func parseReferenceList(path string) ([]domainRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []domainRule
	s := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	s.Buffer(buf, 1024*1024)
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule, err := parseReferenceRule(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		out = append(out, rule)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("reference list is empty")
	}
	return out, nil
}

func parseReferenceRule(line string) (domainRule, error) {
	prefixes := []struct {
		Prefix string
		Type   domainType
	}{
		{"domain:", domainRoot},
		{"full:", domainFull},
		{"regexp:", domainRegex},
		{"regex:", domainRegex},
		{"keyword:", domainPlain},
	}
	for _, p := range prefixes {
		if strings.HasPrefix(line, p.Prefix) {
			value := strings.TrimSpace(strings.TrimPrefix(line, p.Prefix))
			if i := strings.Index(value, " @"); i >= 0 {
				value = value[:i]
			}
			if value == "" {
				return domainRule{}, errors.New("empty rule value")
			}
			return domainRule{Type: p.Type, Value: value}, nil
		}
	}
	if strings.Contains(line, ":") && !looksLikeDomain(line) {
		return domainRule{}, fmt.Errorf("unknown rule syntax %q", line)
	}
	if !looksLikeDomain(line) {
		return domainRule{}, fmt.Errorf("invalid domain rule %q", line)
	}
	return domainRule{Type: domainRoot, Value: line}, nil
}

func looksLikeDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, " /\\\t\r\n") {
		return false
	}
	return strings.Contains(s, ".") || !strings.Contains(s, ":")
}

func compareRuleSets(a, b []domainRule) error {
	ma := make(map[string]int, len(a))
	mb := make(map[string]int, len(b))
	for _, r := range a {
		ma[ruleKey(r)]++
	}
	for _, r := range b {
		mb[ruleKey(r)]++
	}
	if len(ma) == len(mb) {
		equal := true
		for k, va := range ma {
			if mb[k] != va {
				equal = false
				break
			}
		}
		if equal {
			return nil
		}
	}
	var onlyA, onlyB []string
	for k, va := range ma {
		if vb := mb[k]; vb != va {
			onlyA = append(onlyA, k+" x"+strconv.Itoa(va-vb))
		}
	}
	for k, vb := range mb {
		if va := ma[k]; va != vb {
			onlyB = append(onlyB, k+" x"+strconv.Itoa(vb-va))
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	return fmt.Errorf("geosite/reference mismatch: geosite=%d rules (%d unique), reference=%d rules (%d unique); geosite-only=%s; reference-only=%s",
		len(a), len(ma), len(b), len(mb), preview(onlyA), preview(onlyB))
}

func preview(v []string) string {
	const max = 5
	if len(v) == 0 {
		return "[]"
	}
	if len(v) > max {
		return fmt.Sprintf("%q (+%d more)", v[:max], len(v)-max)
	}
	return fmt.Sprintf("%q", v)
}

func ruleKey(r domainRule) string {
	return fmt.Sprintf("%d\x00%s", r.Type, r.Value)
}

func buildAutoProxy(rules []domainRule, listName string) ([]byte, error) {
	set := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		line, err := autoProxyLine(r)
		if err != nil {
			return nil, err
		}
		set[line] = struct{}{}
	}
	lines := make([]string, 0, len(set))
	for line := range set {
		lines = append(lines, line)
	}
	sort.Strings(lines)

	var b bytes.Buffer
	b.WriteString("[AutoProxy 0.2.9]\n")
	b.WriteString("! geosite:")
	b.WriteString(listName)
	b.WriteByte('\n')
	for _, line := range lines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

func autoProxyLine(r domainRule) (string, error) {
	value := strings.TrimSpace(r.Value)
	if value == "" {
		return "", errors.New("empty domain rule")
	}
	switch r.Type {
	case domainRoot:
		if strings.ContainsAny(value, " /\t\r\n") {
			return "", fmt.Errorf("invalid root domain %q", value)
		}
		return "||" + value, nil
	case domainFull:
		return "/^[a-zA-Z][a-zA-Z0-9+.-]*:\\/\\/(?:[^@\\/?#]+@)?" + regexp.QuoteMeta(value) + "(?::\\d+)?(?:\\/|[?#]|$)/", nil
	case domainPlain:
		return "/^[a-zA-Z][a-zA-Z0-9+.-]*:\\/\\/(?:[^@\\/?#]+@)?[^@\\/?#:]*" + regexp.QuoteMeta(value) + "[^@\\/?#:]*(?::\\d+)?(?:\\/|[?#]|$)/", nil
	case domainRegex:
		p, err := convertDomainRegex(value)
		if err != nil {
			return "", fmt.Errorf("regexp %q: %w", value, err)
		}
		return "/" + p + "/", nil
	default:
		return "", fmt.Errorf("unsupported domain type %d", r.Type)
	}
}

func convertDomainRegex(src string) (string, error) {
	if src == "" {
		return "", errors.New("empty regexp")
	}
	if strings.Contains(src, "(?i") || strings.Contains(src, "(?m") || strings.Contains(src, "(?s") ||
		strings.Contains(src, "(?U") || strings.Contains(src, "(?-") || strings.Contains(src, "(?P<") ||
		strings.Contains(src, "\\A") || strings.Contains(src, "\\z") || strings.Contains(src, "\\Z") ||
		strings.Contains(src, "\\Q") || strings.Contains(src, "\\E") || strings.Contains(src, "\\p") ||
		strings.Contains(src, "\\P") || strings.Contains(src, "\\x{") || strings.Contains(src, "[[:") ||
		strings.Contains(src, "[^") || strings.Contains(src, "\\S") || strings.Contains(src, "\\D") || strings.Contains(src, "\\W") {
		return "", errors.New("regexp contains syntax that cannot be converted safely to a host-only SwitchyOmega JavaScript regex")
	}

	anchoredStart := strings.HasPrefix(src, "^")
	if anchoredStart {
		src = src[1:]
	}
	anchoredEnd := hasUnescapedTrailingDollar(src)
	if anchoredEnd {
		src = src[:len(src)-1]
	}

	body, err := restrictRegexToHost(src)
	if err != nil {
		return "", err
	}
	if _, err := regexp.Compile("^(?:" + src + ")$"); err != nil {
		return "", fmt.Errorf("invalid Go regexp: %w", err)
	}

	var b strings.Builder
	b.WriteString("^[a-zA-Z][a-zA-Z0-9+.-]*:\\/\\/(?:[^@\\/?#]+@)?")
	if !anchoredStart {
		b.WriteString("[^@\\/?#:]*")
	}
	b.WriteString("(?:")
	b.WriteString(body)
	b.WriteString(")")
	if !anchoredEnd {
		b.WriteString("[^@\\/?#:]*")
	}
	b.WriteString("(?::\\d+)?(?:\\/|[?#]|$)")
	return b.String(), nil
}

func hasUnescapedTrailingDollar(s string) bool {
	if !strings.HasSuffix(s, "$") {
		return false
	}
	backslashes := 0
	for i := len(s) - 2; i >= 0 && s[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 == 0
}

func restrictRegexToHost(src string) (string, error) {
	var b strings.Builder
	inClass := false
	escaped := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if escaped {
			b.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			b.WriteByte(c)
			escaped = true
			continue
		}
		if c == '[' {
			inClass = true
			b.WriteByte(c)
			continue
		}
		if c == ']' && inClass {
			inClass = false
			b.WriteByte(c)
			continue
		}
		if !inClass && (c == '^' || c == '$') {
			return "", fmt.Errorf("internal anchor %q cannot be converted safely", string(c))
		}
		if !inClass && c == '.' {
			b.WriteString("[^@\\/?#:]")
			continue
		}
		b.WriteByte(c)
	}
	if escaped {
		return "", errors.New("regexp ends with an incomplete escape")
	}
	if inClass {
		return "", errors.New("regexp has an unterminated character class")
	}
	return b.String(), nil
}
