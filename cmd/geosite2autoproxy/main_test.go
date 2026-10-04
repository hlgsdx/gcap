package main

import (
	"encoding/base64"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestExtractGeoSiteAllTypesAndUnknownFields(t *testing.T) {
	cn := encGeoSite("CN", []domainRule{
		{domainRoot, "example.cn"},
		{domainFull, "full.example.cn"},
		{domainRegex, `^cdn\d\.example\.cn$`},
		{domainPlain, "needle"},
	}, true)
	us := encGeoSite("US", []domainRule{{domainRoot, "example.com"}}, false)
	blob := append(encBytesField(1, us), encBytesField(1, cn)...)

	rules, err := extractGeoSite(blob, "cn")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("got %d rules, want 4", len(rules))
	}
	if rules[0].Type != domainRoot || rules[0].Value != "example.cn" {
		t.Fatalf("unexpected first rule: %#v", rules[0])
	}
}

func TestAutoProxySemantics(t *testing.T) {
	cases := []struct {
		rule    domainRule
		match   []string
		nomatch []string
	}{
		{
			domainRule{domainRoot, "example.cn"},
			[]string{"http://example.cn/", "https://a.example.cn/x"},
			[]string{"https://example.cn.evil/x", "https://notexample.cn/"},
		},
		{
			domainRule{domainFull, "full.example.cn"},
			[]string{"http://full.example.cn/", "https://full.example.cn:8443/x"},
			[]string{"https://a.full.example.cn/", "https://full.example.cn.evil/"},
		},
		{
			domainRule{domainPlain, "needle"},
			[]string{"https://a-needle-b.example.cn/"},
			[]string{"https://example.cn/path/needle", "https://example.cn/?q=needle", "https://userneedle@example.cn/"},
		},
		{
			domainRule{domainRegex, `^cdn\d-epicgames-\d+\.file\.myqcloud\.com$`},
			[]string{"https://cdn7-epicgames-123.file.myqcloud.com/x"},
			[]string{"https://x.cdn7-epicgames-123.file.myqcloud.com/x"},
		},
		{
			domainRule{domainRegex, `.+\.awsdns-cn-[0-9][0-9]\.(biz|com|net|top)$`},
			[]string{"https://x.awsdns-cn-12.com/"},
			[]string{"https://awsdns-cn-12.com/", "https://x.awsdns-cn-12.com.evil/"},
		},
	}

	for _, tc := range cases {
		line, err := autoProxyLine(tc.rule)
		if err != nil {
			t.Fatalf("%#v: %v", tc.rule, err)
		}
		for _, u := range tc.match {
			if !matchAutoProxyLine(line, u) {
				t.Errorf("rule %q should match %q", line, u)
			}
		}
		for _, u := range tc.nomatch {
			if matchAutoProxyLine(line, u) {
				t.Errorf("rule %q should not match %q", line, u)
			}
		}
	}
}

func TestBuildAutoProxyDeterministicAndBase64RoundTrip(t *testing.T) {
	rules := []domainRule{
		{domainRoot, "b.cn"},
		{domainRoot, "a.cn"},
		{domainRoot, "a.cn"},
	}
	plain, err := buildAutoProxy(rules, "cn")
	if err != nil {
		t.Fatal(err)
	}
	want := "[AutoProxy 0.2.9]\n! geosite:cn\n||a.cn\n||b.cn\n"
	if string(plain) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", plain, want)
	}
	enc := base64.StdEncoding.EncodeToString(plain)
	dec, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != string(plain) {
		t.Fatal("base64 round-trip mismatch")
	}
}

func TestReferenceValidation(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "direct-list-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("example.cn\nfull:full.example.cn\nregexp:^cdn\\d\\.example\\.cn$\nkeyword:needle\n")
	_ = f.Close()
	ref, err := parseReferenceList(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	got := []domainRule{
		{domainRoot, "example.cn"},
		{domainFull, "full.example.cn"},
		{domainRegex, `^cdn\d\.example\.cn$`},
		{domainPlain, "needle"},
	}
	if err := compareRuleSets(got, ref); err != nil {
		t.Fatal(err)
	}
}

func TestCurrentCNRegexSamplesConvert(t *testing.T) {
	patterns := []string{
		`.+\.awsdns-cn-[0-9][0-9]\.(biz|com|net|top)$`,
		`.+\.awsdns-cn-[0-9][a-e0-9]\.cn$`,
		`^(.+\.)*zh\.okaapps\.com$`,
		`^.+-mihayo\.akamaized\.net$`,
		`^cdn\d-epicgames-\d+\.file\.myqcloud\.com$`,
		`^epicgames-download\d-\d+\.file\.myqcloud\.com$`,
		`^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.googlevideo\.com$`,
		`^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.xn--ngstr-lra8j\.com$`,
	}
	for _, p := range patterns {
		if _, err := convertDomainRegex(p); err != nil {
			t.Errorf("current CN regexp %q failed conversion: %v", p, err)
		}
	}
}

func TestRejectUnsafeRegexTranslation(t *testing.T) {
	for _, p := range []string{`(?i)^example\.cn$`, `^foo$|^bar$`, `[[:alpha:]]+\.cn$`} {
		if _, err := convertDomainRegex(p); err == nil {
			t.Errorf("expected unsafe regexp %q to be rejected", p)
		}
	}
}

func matchAutoProxyLine(line, rawURL string) bool {
	if strings.HasPrefix(line, "||") {
		host := hostOf(rawURL)
		domain := strings.TrimPrefix(line, "||")
		return host == domain || strings.HasSuffix(host, "."+domain)
	}
	if strings.HasPrefix(line, "/") && strings.HasSuffix(line, "/") {
		p := strings.TrimSuffix(strings.TrimPrefix(line, "/"), "/")
		r := regexp.MustCompile(p)
		return r.MatchString(rawURL)
	}
	panic("unsupported test AutoProxy rule: " + line)
}

func hostOf(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

func encGeoSite(code string, rules []domainRule, unknown bool) []byte {
	var b []byte
	b = append(b, encBytesField(1, []byte(code))...)
	for _, r := range rules {
		var d []byte
		if r.Type != domainPlain {
			d = append(d, encVarintField(1, uint64(r.Type))...)
		}
		d = append(d, encBytesField(2, []byte(r.Value))...)
		if unknown {
			d = append(d, encBytesField(3, encBytesField(1, []byte("attr")))...)
		}
		b = append(b, encBytesField(2, d)...)
	}
	if unknown {
		b = append(b, encBytesField(4, []byte("ignored"))...)
	}
	return b
}

func encBytesField(field uint64, v []byte) []byte {
	b := encVarint((field << 3) | 2)
	b = append(b, encVarint(uint64(len(v)))...)
	return append(b, v...)
}

func encVarintField(field, v uint64) []byte {
	b := encVarint(field << 3)
	return append(b, encVarint(v)...)
}

func encVarint(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}
