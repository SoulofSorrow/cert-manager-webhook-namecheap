package namecheap

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestSplitDomain(t *testing.T) {
	cases := []struct {
		input   string
		wantSLD string
		wantTLD string
		wantErr bool
	}{
		{"example.com", "example", "com", false},
		{"example.com.", "example", "com", false},
		{"foo.example.com", "example", "com", false},
		{"invalid", "", "", true},
		{"", "", "", true},
		{".", "", "", true},
		{"example.", "", "", true},
	}

	for _, c := range cases {
		sld, tld, err := SplitDomain(c.input)
		if c.wantErr {
			if err == nil {
				t.Errorf("SplitDomain(%q): expected error, got nil", c.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("SplitDomain(%q): unexpected error: %v", c.input, err)
			continue
		}
		if sld != c.wantSLD || tld != c.wantTLD {
			t.Errorf("SplitDomain(%q): got sld=%q tld=%q, want sld=%q tld=%q",
				c.input, sld, tld, c.wantSLD, c.wantTLD)
		}
	}
}

func TestTTLOrDefault(t *testing.T) {
	if ttlOrDefault("") != "1800" {
		t.Error("empty TTL should default to 1800")
	}
	if ttlOrDefault("60") != "60" {
		t.Error("explicit TTL should be preserved")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("short string should not be truncated, got %q", got)
	}
	if got := truncate("hello world", 5); got != "hello..." {
		t.Errorf("truncate mismatch: got %q", got)
	}
}

func TestFormatCAAValue(t *testing.T) {
	got := formatCAAValue("issue", "letsencrypt.org")
	want := `0 issue "letsencrypt.org"`
	if got != want {
		t.Errorf("formatCAAValue: got %q, want %q", got, want)
	}
}

func TestPublicIPCached(t *testing.T) {
	calls := 0
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua == "" {
			t.Error("User-Agent header should be set")
		}
		calls++
		w.Write([]byte("1.2.3.4"))
	}))
	defer ipSrv.Close()

	client := NewClient("user", "key", "user").WithIPEndpoint(ipSrv.URL)

	ip1, err := client.PublicIP()
	if err != nil || ip1 != "1.2.3.4" {
		t.Fatalf("unexpected ip=%q err=%v", ip1, err)
	}
	ip2, _ := client.PublicIP()
	if ip2 != "1.2.3.4" {
		t.Errorf("expected cached IP, got %q", ip2)
	}
	if calls != 1 {
		t.Errorf("expected 1 IP lookup call (cached), got %d", calls)
	}
}

func TestPublicIPHTTPError(t *testing.T) {
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ipSrv.Close()

	client := NewClient("user", "key", "user").WithIPEndpoint(ipSrv.URL)
	_, err := client.PublicIP()
	if err == nil {
		t.Fatal("expected error on HTTP 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}

func TestAddTXTRecord(t *testing.T) {
	existingHosts := []Host{
		{Name: "@", Type: "A", Address: "1.2.3.4", TTL: "1800"},
		{Name: "www", Type: "CNAME", Address: "example.com.", TTL: "1800"},
	}
	var capturedHosts []Host

	ipSrv, apiSrv := newTestServers(t, &existingHosts, &capturedHosts)
	defer ipSrv.Close()
	defer apiSrv.Close()

	client := NewClient("user", "key", "user").
		WithEndpoint(apiSrv.URL).
		WithIPEndpoint(ipSrv.URL)

	if err := client.AddTXTRecord("example.com", "_acme-challenge", "token123"); err != nil {
		t.Fatalf("AddTXTRecord: %v", err)
	}

	if len(capturedHosts) != 3 {
		t.Fatalf("expected 3 hosts after add, got %d", len(capturedHosts))
	}
	last := capturedHosts[2]
	if last.Name != "_acme-challenge" || last.Type != "TXT" || last.Address != "token123" {
		t.Errorf("unexpected TXT record: %+v", last)
	}
}

func TestRemoveTXTRecord(t *testing.T) {
	existingHosts := []Host{
		{Name: "@", Type: "A", Address: "1.2.3.4", TTL: "1800"},
		{Name: "_acme-challenge", Type: "TXT", Address: "token123", TTL: "60"},
	}
	var capturedHosts []Host

	ipSrv, apiSrv := newTestServers(t, &existingHosts, &capturedHosts)
	defer ipSrv.Close()
	defer apiSrv.Close()

	client := NewClient("user", "key", "user").
		WithEndpoint(apiSrv.URL).
		WithIPEndpoint(ipSrv.URL)

	if err := client.RemoveTXTRecord("example.com", "_acme-challenge", "token123"); err != nil {
		t.Fatalf("RemoveTXTRecord: %v", err)
	}

	if len(capturedHosts) != 1 {
		t.Fatalf("expected 1 host after remove, got %d", len(capturedHosts))
	}
	if capturedHosts[0].Type == "TXT" {
		t.Errorf("TXT record should have been removed")
	}
}

func TestRemoveTXTRecord_NoMatchIsIdempotent(t *testing.T) {
	existingHosts := []Host{
		{Name: "@", Type: "A", Address: "1.2.3.4", TTL: "1800"},
	}
	setHostsCalled := false

	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("1.2.3.4"))
	}))
	defer ipSrv.Close()

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		cmd := r.FormValue("Command")
		w.Header().Set("Content-Type", "text/xml")
		switch cmd {
		case "namecheap.domains.dns.getHosts":
			resp := mockGetHostsResponse{Status: "OK"}
			resp.CommandResponse.DomainDNSGetHostsResult.Hosts = existingHosts
			xml.NewEncoder(w).Encode(resp)
		case "namecheap.domains.dns.setHosts":
			setHostsCalled = true
			w.Write([]byte(`<ApiResponse Status="OK"><CommandResponse /></ApiResponse>`))
		default:
			t.Errorf("unexpected command: %s", cmd)
		}
	}))
	defer apiSrv.Close()

	client := NewClient("user", "key", "user").
		WithEndpoint(apiSrv.URL).
		WithIPEndpoint(ipSrv.URL)

	// Remove a non-existent record — should succeed silently without calling setHosts
	if err := client.RemoveTXTRecord("example.com", "_acme-challenge", "nonexistent"); err != nil {
		t.Fatalf("RemoveTXTRecord should be idempotent: %v", err)
	}

	if setHostsCalled {
		t.Error("setHosts should not be called when there is nothing to remove")
	}
}

func TestRemoveTXTRecord_OnlyMatchingRemoved(t *testing.T) {
	existingHosts := []Host{
		{Name: "@", Type: "A", Address: "1.2.3.4", TTL: "1800"},
		{Name: "_acme-challenge", Type: "TXT", Address: "token123", TTL: "60"},
		{Name: "_acme-challenge", Type: "TXT", Address: "other-token", TTL: "60"},
	}
	var capturedHosts []Host

	ipSrv, apiSrv := newTestServers(t, &existingHosts, &capturedHosts)
	defer ipSrv.Close()
	defer apiSrv.Close()

	client := NewClient("user", "key", "user").
		WithEndpoint(apiSrv.URL).
		WithIPEndpoint(ipSrv.URL)

	if err := client.RemoveTXTRecord("example.com", "_acme-challenge", "token123"); err != nil {
		t.Fatalf("RemoveTXTRecord: %v", err)
	}

	if len(capturedHosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(capturedHosts))
	}
	for _, h := range capturedHosts {
		if h.Type == "TXT" && h.Address == "token123" {
			t.Errorf("exact-match TXT should be gone: %+v", h)
		}
	}
}

func TestEnsureCAARecords_AddsWhenMissing(t *testing.T) {
	existingHosts := []Host{
		{Name: "@", Type: "A", Address: "1.2.3.4", TTL: "1800"},
	}
	var capturedHosts []Host

	ipSrv, apiSrv := newTestServers(t, &existingHosts, &capturedHosts)
	defer ipSrv.Close()
	defer apiSrv.Close()

	client := NewClient("user", "key", "user").
		WithEndpoint(apiSrv.URL).
		WithIPEndpoint(ipSrv.URL)

	if err := client.EnsureCAARecords("example.com", "letsencrypt.org"); err != nil {
		t.Fatalf("EnsureCAARecords: %v", err)
	}

	var caaRecords []Host
	for _, h := range capturedHosts {
		if h.Type == "CAA" {
			caaRecords = append(caaRecords, h)
		}
	}

	if len(caaRecords) != 2 {
		t.Fatalf("expected 2 CAA records, got %d: %+v", len(caaRecords), caaRecords)
	}

	hasIssue, hasIssueWild := false, false
	for _, h := range caaRecords {
		if strings.Contains(h.Address, "issuewild") {
			hasIssueWild = true
		} else if strings.Contains(h.Address, "issue") {
			hasIssue = true
		}
	}
	if !hasIssue {
		t.Error("missing CAA issue record")
	}
	if !hasIssueWild {
		t.Error("missing CAA issuewild record")
	}
}

func TestEnsureCAARecords_NoDuplicates(t *testing.T) {
	existingHosts := []Host{
		{Name: "@", Type: "A", Address: "1.2.3.4", TTL: "1800"},
		{Name: "@", Type: "CAA", Address: `0 issue "letsencrypt.org"`, TTL: "3600"},
		{Name: "@", Type: "CAA", Address: `0 issuewild "letsencrypt.org"`, TTL: "3600"},
	}
	var capturedHosts []Host

	ipSrv, apiSrv := newTestServers(t, &existingHosts, &capturedHosts)
	defer ipSrv.Close()
	defer apiSrv.Close()

	client := NewClient("user", "key", "user").
		WithEndpoint(apiSrv.URL).
		WithIPEndpoint(ipSrv.URL)

	if err := client.EnsureCAARecords("example.com", "letsencrypt.org"); err != nil {
		t.Fatalf("EnsureCAARecords: %v", err)
	}

	if len(capturedHosts) != 0 {
		t.Errorf("setHosts should not be called when CAA records already exist, got %d hosts written", len(capturedHosts))
	}
}

func TestEnsureCAARecords_AddsMissingWildcard(t *testing.T) {
	existingHosts := []Host{
		{Name: "@", Type: "CAA", Address: `0 issue "letsencrypt.org"`, TTL: "3600"},
		// issuewild is missing
	}
	var capturedHosts []Host

	ipSrv, apiSrv := newTestServers(t, &existingHosts, &capturedHosts)
	defer ipSrv.Close()
	defer apiSrv.Close()

	client := NewClient("user", "key", "user").
		WithEndpoint(apiSrv.URL).
		WithIPEndpoint(ipSrv.URL)

	if err := client.EnsureCAARecords("example.com", "letsencrypt.org"); err != nil {
		t.Fatalf("EnsureCAARecords: %v", err)
	}

	hasIssueWild := false
	for _, h := range capturedHosts {
		if h.Type == "CAA" && strings.Contains(h.Address, "issuewild") {
			hasIssueWild = true
		}
	}
	if !hasIssueWild {
		t.Error("issuewild should have been added")
	}
}

func TestAPIError(t *testing.T) {
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("1.2.3.4"))
	}))
	defer ipSrv.Close()

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(`<ApiResponse Status="ERROR"><Errors><Error Number="2030166">Domain is invalid</Error></Errors></ApiResponse>`))
	}))
	defer apiSrv.Close()

	client := NewClient("user", "key", "user").
		WithEndpoint(apiSrv.URL).
		WithIPEndpoint(ipSrv.URL)

	_, err := client.GetHosts("bad", "domain")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "2030166") {
		t.Errorf("expected error number in message, got: %v", err)
	}
	if !strings.Contains(err.Error(), "Domain is invalid") {
		t.Errorf("expected error text in message, got: %v", err)
	}
}

func TestAPIHTTPError(t *testing.T) {
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("1.2.3.4"))
	}))
	defer ipSrv.Close()

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("upstream timeout"))
	}))
	defer apiSrv.Close()

	client := NewClient("user", "key", "user").
		WithEndpoint(apiSrv.URL).
		WithIPEndpoint(ipSrv.URL)

	_, err := client.GetHosts("example", "com")
	if err == nil {
		t.Fatal("expected error on HTTP 502, got nil")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}

func TestAPICallUsesPOST(t *testing.T) {
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("1.2.3.4"))
	}))
	defer ipSrv.Close()

	gotMethod := ""
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(`<ApiResponse Status="OK"><CommandResponse><DomainDNSGetHostsResult /></CommandResponse></ApiResponse>`))
	}))
	defer apiSrv.Close()

	client := NewClient("user", "key", "user").
		WithEndpoint(apiSrv.URL).
		WithIPEndpoint(ipSrv.URL)

	_, _ = client.GetHosts("example", "com")

	if gotMethod != http.MethodPost {
		t.Errorf("expected POST method, got %s", gotMethod)
	}
}

// --- mock server helpers ---

type mockGetHostsResponse struct {
	XMLName         xml.Name `xml:"ApiResponse"`
	Status          string   `xml:"Status,attr"`
	CommandResponse struct {
		DomainDNSGetHostsResult struct {
			Hosts []Host `xml:"host"`
		} `xml:"DomainDNSGetHostsResult"`
	} `xml:"CommandResponse"`
}

func newTestServers(t *testing.T, existing *[]Host, captured *[]Host) (*httptest.Server, *httptest.Server) {
	t.Helper()

	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("1.2.3.4"))
	}))

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		cmd := r.FormValue("Command")
		w.Header().Set("Content-Type", "text/xml")

		switch cmd {
		case "namecheap.domains.dns.getHosts":
			resp := mockGetHostsResponse{Status: "OK"}
			resp.CommandResponse.DomainDNSGetHostsResult.Hosts = *existing
			xml.NewEncoder(w).Encode(resp)

		case "namecheap.domains.dns.setHosts":
			hosts := parseSetHostsFromForm(r)
			*captured = hosts
			*existing = hosts
			w.Write([]byte(`<ApiResponse Status="OK"><CommandResponse /></ApiResponse>`))

		default:
			t.Errorf("unexpected API command: %s", cmd)
			http.Error(w, "unknown", 400)
		}
	}))

	return ipSrv, apiSrv
}

func parseSetHostsFromForm(r *http.Request) []Host {
	var hosts []Host
	for i := 1; ; i++ {
		n := strconv.Itoa(i)
		name := r.FormValue("HostName" + n)
		if name == "" {
			break
		}
		hosts = append(hosts, Host{
			Name:    name,
			Type:    r.FormValue("RecordType" + n),
			Address: r.FormValue("Address" + n),
			TTL:     r.FormValue("TTL" + n),
		})
	}
	return hosts
}
