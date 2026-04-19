// Package dryrun implements pre-flight checks for the Namecheap webhook.
// It verifies connectivity, credentials, IP resolution, and DNS record
// operations without making any permanent changes.
package dryrun

import (
	"fmt"
	"strings"
	"time"

	"github.com/yourusername/cert-manager-webhook-namecheap/pkg/namecheap"
)

// Result holds the outcome of a single check.
type Result struct {
	Name    string
	OK      bool
	Detail  string
	Elapsed time.Duration
}

func (r Result) String() string {
	status := "ok"
	if !r.OK {
		status = "fail"
	}
	s := fmt.Sprintf("[%s] %s (%s)", status, r.Name, r.Elapsed.Round(time.Millisecond))
	if r.Detail != "" {
		s += "\n       " + r.Detail
	}
	return s
}

// Report is the full dry run result.
type Report struct {
	Domain  string
	Results []Result
}

// OK returns true if all checks passed.
func (r *Report) OK() bool {
	for _, res := range r.Results {
		if !res.OK {
			return false
		}
	}
	return true
}

func (r *Report) String() string {
	lines := []string{
		fmt.Sprintf("dry run for domain: %s", r.Domain),
		strings.Repeat("-", 48),
	}
	for _, res := range r.Results {
		lines = append(lines, res.String())
	}
	lines = append(lines, strings.Repeat("-", 48))
	if r.OK() {
		lines = append(lines, "result: all checks passed")
	} else {
		lines = append(lines, "result: one or more checks failed")
	}
	return strings.Join(lines, "\n")
}

// Run executes all dry run checks against the given domain and returns a Report.
// No DNS records are written. The TXT record check reads existing records and
// simulates the merge without calling setHosts.
func Run(client *namecheap.Client, domain string) *Report {
	report := &Report{Domain: domain}

	report.Results = append(report.Results, checkEgressIP(client))
	report.Results = append(report.Results, checkCredentials(client, domain))
	report.Results = append(report.Results, checkDNSReadWrite(client, domain))
	report.Results = append(report.Results, checkCAAStatus(client, domain))

	return report
}

// --- individual checks ---

// checkEgressIP verifies that the public IP can be resolved.
func checkEgressIP(client *namecheap.Client) Result {
	start := time.Now()
	ip, err := client.PublicIP()
	elapsed := time.Since(start)

	if err != nil {
		return Result{
			Name:    "egress IP resolution",
			OK:      false,
			Detail:  err.Error(),
			Elapsed: elapsed,
		}
	}
	return Result{
		Name:    "egress IP resolution",
		OK:      true,
		Detail:  fmt.Sprintf("resolved: %s", ip),
		Elapsed: elapsed,
	}
}

// checkCredentials verifies that the Namecheap API is reachable and the
// credentials are valid by fetching the host list for the domain.
func checkCredentials(client *namecheap.Client, domain string) Result {
	start := time.Now()

	sld, tld, err := namecheap.SplitDomain(domain)
	if err != nil {
		return Result{
			Name:    "API credentials",
			OK:      false,
			Detail:  err.Error(),
			Elapsed: time.Since(start),
		}
	}

	// A successful getHosts call proves API access + valid credentials + whitelisted IP
	hosts, err := client.GetHosts(sld, tld)
	elapsed := time.Since(start)

	if err != nil {
		return Result{
			Name:    "API credentials",
			OK:      false,
			Detail:  err.Error(),
			Elapsed: elapsed,
		}
	}
	return Result{
		Name:    "API credentials",
		OK:      true,
		Detail:  fmt.Sprintf("API reachable, credentials valid, %d existing records found", len(hosts)),
		Elapsed: elapsed,
	}
}

// checkDNSReadWrite simulates adding and removing a TXT record without
// actually calling setHosts. It reads existing records and verifies the
// merge logic would produce the correct result.
func checkDNSReadWrite(client *namecheap.Client, domain string) Result {
	start := time.Now()

	sld, tld, err := namecheap.SplitDomain(domain)
	if err != nil {
		return Result{
			Name:    "DNS record simulation",
			OK:      false,
			Detail:  err.Error(),
			Elapsed: time.Since(start),
		}
	}

	hosts, err := client.GetHosts(sld, tld)
	elapsed := time.Since(start)
	if err != nil {
		return Result{
			Name:    "DNS record simulation",
			OK:      false,
			Detail:  fmt.Sprintf("getHosts failed: %v", err),
			Elapsed: elapsed,
		}
	}

	// Simulate add
	testRecord := namecheap.Host{
		Name:    "_acme-challenge-dryrun",
		Type:    "TXT",
		Address: "dry-run-token",
		TTL:     "60",
	}
	merged := append(hosts, testRecord)

	// Simulate remove
	filtered := make([]namecheap.Host, 0, len(merged))
	for _, h := range merged {
		if h.Type == "TXT" && h.Name == testRecord.Name && h.Address == testRecord.Address {
			continue
		}
		filtered = append(filtered, h)
	}

	if len(filtered) != len(hosts) {
		return Result{
			Name:    "DNS record simulation",
			OK:      false,
			Detail:  fmt.Sprintf("merge/filter mismatch: started with %d, ended with %d", len(hosts), len(filtered)),
			Elapsed: elapsed,
		}
	}

	return Result{
		Name:    "DNS record simulation",
		OK:      true,
		Detail:  fmt.Sprintf("add/remove simulation passed (no writes performed), base record count: %d", len(hosts)),
		Elapsed: elapsed,
	}
}

// checkCAAStatus reads existing CAA records and reports their state.
// Does not modify anything.
func checkCAAStatus(client *namecheap.Client, domain string) Result {
	start := time.Now()

	sld, tld, err := namecheap.SplitDomain(domain)
	if err != nil {
		return Result{
			Name:    "CAA record status",
			OK:      false,
			Detail:  err.Error(),
			Elapsed: time.Since(start),
		}
	}

	hosts, err := client.GetHosts(sld, tld)
	elapsed := time.Since(start)
	if err != nil {
		return Result{
			Name:    "CAA record status",
			OK:      false,
			Detail:  fmt.Sprintf("getHosts failed: %v", err),
			Elapsed: elapsed,
		}
	}

	var caaRecords []string
	hasIssue := false
	hasIssueWild := false

	for _, h := range hosts {
		if h.Type != "CAA" {
			continue
		}
		caaRecords = append(caaRecords, fmt.Sprintf("%s %s", h.Name, h.Address))
		if strings.Contains(h.Address, "letsencrypt.org") {
			if strings.Contains(h.Address, "issuewild") {
				hasIssueWild = true
			} else if strings.Contains(h.Address, "issue") {
				hasIssue = true
			}
		}
	}

	if len(caaRecords) == 0 {
		return Result{
			Name:    "CAA record status",
			OK:      true,
			Detail:  "no CAA records found — all CAs may issue (webhook will add letsencrypt.org records automatically)",
			Elapsed: elapsed,
		}
	}

	status := strings.Join(caaRecords, ", ")
	if hasIssue && hasIssueWild {
		return Result{
			Name:    "CAA record status",
			OK:      true,
			Detail:  fmt.Sprintf("letsencrypt.org authorized for issue + issuewild: %s", status),
			Elapsed: elapsed,
		}
	}
	if hasIssue {
		return Result{
			Name:    "CAA record status",
			OK:      false,
			Detail:  fmt.Sprintf("letsencrypt.org has issue but not issuewild — wildcard certs will fail: %s", status),
			Elapsed: elapsed,
		}
	}

	return Result{
		Name:    "CAA record status",
		OK:      false,
		Detail:  fmt.Sprintf("CAA records exist but letsencrypt.org is not authorized — cert issuance will fail: %s", status),
		Elapsed: elapsed,
	}
}
