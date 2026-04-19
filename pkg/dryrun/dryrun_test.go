package dryrun

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/yourusername/cert-manager-webhook-namecheap/pkg/namecheap"
)

// --- test helpers ---

type mockHosts struct {
	hosts []namecheap.Host
}

type mockGetHostsResponse struct {
	XMLName         xml.Name `xml:"ApiResponse"`
	Status          string   `xml:"Status,attr"`
	CommandResponse struct {
		DomainDNSGetHostsResult struct {
			Hosts []namecheap.Host `xml:"host"`
		} `xml:"DomainDNSGetHostsResult"`
	} `xml:"CommandResponse"`
}

func newTestClient(t *testing.T, m *mockHosts) (*namecheap.Client, func()) {
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
			resp.CommandResponse.DomainDNSGetHostsResult.Hosts = m.hosts
			xml.NewEncoder(w).Encode(resp)

		case "namecheap.domains.dns.setHosts":
			// Parse and update for write tests
			var updated []namecheap.Host
			for i := 1; ; i++ {
				n := strconv.Itoa(i)
				name := r.FormValue("HostName" + n)
				if name == "" {
					break
				}
				updated = append(updated, namecheap.Host{
					Name:    name,
					Type:    r.FormValue("RecordType" + n),
					Address: r.FormValue("Address" + n),
					TTL:     r.FormValue("TTL" + n),
				})
			}
			m.hosts = updated
			w.Write([]byte(`<ApiResponse Status="OK"><CommandResponse /></ApiResponse>`))

		default:
			t.Errorf("unexpected API command: %s", cmd)
			http.Error(w, "unknown", 400)
		}
	}))

	client := namecheap.NewClient("user", "key", "user").
		WithEndpoint(apiSrv.URL).
		WithIPEndpoint(ipSrv.URL)

	cleanup := func() {
		ipSrv.Close()
		apiSrv.Close()
	}

	return client, cleanup
}

// --- tests ---

func TestRunAllChecksPass(t *testing.T) {
	m := &mockHosts{
		hosts: []namecheap.Host{
			{Name: "@", Type: "A", Address: "1.2.3.4", TTL: "1800"},
		},
	}

	client, cleanup := newTestClient(t, m)
	defer cleanup()

	report := Run(client, "example.com")

	if !report.OK() {
		t.Errorf("expected all checks to pass, got:\n%s", report.String())
	}
	if len(report.Results) != 4 {
		t.Errorf("expected 4 results, got %d", len(report.Results))
	}
}

func TestRunNoDNSWrite(t *testing.T) {
	initialCount := 2
	m := &mockHosts{
		hosts: []namecheap.Host{
			{Name: "@", Type: "A", Address: "1.2.3.4", TTL: "1800"},
			{Name: "www", Type: "CNAME", Address: "example.com.", TTL: "1800"},
		},
	}

	client, cleanup := newTestClient(t, m)
	defer cleanup()

	Run(client, "example.com")

	// No writes should have happened — record count must be unchanged
	if len(m.hosts) != initialCount {
		t.Errorf("dry run should not write DNS records: started with %d, ended with %d",
			initialCount, len(m.hosts))
	}
}

func TestCAAStatusMissing(t *testing.T) {
	m := &mockHosts{
		hosts: []namecheap.Host{
			{Name: "@", Type: "A", Address: "1.2.3.4", TTL: "1800"},
		},
	}

	client, cleanup := newTestClient(t, m)
	defer cleanup()

	report := Run(client, "example.com")

	var caaResult *Result
	for i := range report.Results {
		if report.Results[i].Name == "CAA record status" {
			caaResult = &report.Results[i]
			break
		}
	}

	if caaResult == nil {
		t.Fatal("CAA result not found")
	}
	// No CAA = OK (webhook will add them automatically)
	if !caaResult.OK {
		t.Errorf("no CAA records should be OK (webhook adds them): %s", caaResult.Detail)
	}
	if !strings.Contains(caaResult.Detail, "automatically") {
		t.Errorf("detail should mention automatic CAA management: %s", caaResult.Detail)
	}
}

func TestCAAStatusAuthorized(t *testing.T) {
	m := &mockHosts{
		hosts: []namecheap.Host{
			{Name: "@", Type: "CAA", Address: `0 issue "letsencrypt.org"`, TTL: "3600"},
			{Name: "@", Type: "CAA", Address: `0 issuewild "letsencrypt.org"`, TTL: "3600"},
		},
	}

	client, cleanup := newTestClient(t, m)
	defer cleanup()

	report := Run(client, "example.com")

	for _, res := range report.Results {
		if res.Name == "CAA record status" {
			if !res.OK {
				t.Errorf("expected CAA check to pass when letsencrypt.org is authorized: %s", res.Detail)
			}
			return
		}
	}
	t.Fatal("CAA result not found")
}

func TestCAAStatusMissingWildcard(t *testing.T) {
	m := &mockHosts{
		hosts: []namecheap.Host{
			// Only issue, no issuewild -> wildcard certs will fail
			{Name: "@", Type: "CAA", Address: `0 issue "letsencrypt.org"`, TTL: "3600"},
		},
	}

	client, cleanup := newTestClient(t, m)
	defer cleanup()

	report := Run(client, "example.com")

	for _, res := range report.Results {
		if res.Name == "CAA record status" {
			if res.OK {
				t.Errorf("expected CAA check to fail when issuewild is missing")
			}
			if !strings.Contains(res.Detail, "issuewild") {
				t.Errorf("detail should mention issuewild: %s", res.Detail)
			}
			return
		}
	}
	t.Fatal("CAA result not found")
}

func TestReportString(t *testing.T) {
	m := &mockHosts{hosts: []namecheap.Host{{Name: "@", Type: "A", Address: "1.2.3.4", TTL: "1800"}}}
	client, cleanup := newTestClient(t, m)
	defer cleanup()

	report := Run(client, "example.com")
	s := report.String()

	if !strings.Contains(s, "example.com") {
		t.Errorf("report string should contain domain")
	}
	if !strings.Contains(s, "all checks passed") {
		t.Errorf("report string should contain summary: %s", s)
	}
}
