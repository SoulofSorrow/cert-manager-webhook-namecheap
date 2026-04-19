package namecheap

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultAPIEndpoint = "https://api.namecheap.com/xml.response"
	defaultIPEndpoint  = "https://api.ipify.org"
	ipCacheDuration    = 5 * time.Minute
	defaultTimeout     = 30 * time.Second
	userAgent          = "cert-manager-webhook-namecheap/1.0"
)

// Client communicates with the Namecheap API.
// The public egress IP is resolved automatically and cached — it does not need
// to be provided as configuration.
type Client struct {
	apiUser    string
	apiKey     string
	username   string
	endpoint   string
	ipEndpoint string
	httpClient *http.Client

	ipMu        sync.Mutex
	cachedIP    string
	ipFetchedAt time.Time
}

func NewClient(apiUser, apiKey, username string) *Client {
	return &Client{
		apiUser:    apiUser,
		apiKey:     apiKey,
		username:   username,
		endpoint:   defaultAPIEndpoint,
		ipEndpoint: defaultIPEndpoint,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
}

// WithEndpoint overrides the Namecheap API endpoint — used in tests.
func (c *Client) WithEndpoint(endpoint string) *Client {
	c.endpoint = endpoint
	return c
}

// WithIPEndpoint overrides the public IP lookup endpoint — used in tests.
func (c *Client) WithIPEndpoint(ipEndpoint string) *Client {
	c.ipEndpoint = ipEndpoint
	return c
}

// --- XML response types ---

type apiResponse struct {
	XMLName xml.Name `xml:"ApiResponse"`
	Status  string   `xml:"Status,attr"`
	Errors  []struct {
		Message string `xml:",chardata"`
		Number  string `xml:"Number,attr"`
	} `xml:"Errors>Error"`
	CommandResponse struct {
		DomainDNSGetHostsResult struct {
			Hosts []Host `xml:"host"`
		} `xml:"DomainDNSGetHostsResult"`
	} `xml:"CommandResponse"`
}

// Host represents a single DNS record in the Namecheap API.
type Host struct {
	HostID  string `xml:"HostId,attr"`
	Name    string `xml:"Name,attr"`
	Type    string `xml:"Type,attr"`
	Address string `xml:"Address,attr"`
	MXPref  string `xml:"MXPref,attr"`
	TTL     string `xml:"TTL,attr"`
}

// --- Public API ---

func (c *Client) GetHosts(sld, tld string) ([]Host, error) {
	params, err := c.baseParams("namecheap.domains.dns.getHosts")
	if err != nil {
		return nil, err
	}
	params.Set("SLD", sld)
	params.Set("TLD", tld)

	resp, err := c.call(params)
	if err != nil {
		return nil, err
	}
	return resp.CommandResponse.DomainDNSGetHostsResult.Hosts, nil
}

func (c *Client) SetHosts(sld, tld string, hosts []Host) error {
	params, err := c.baseParams("namecheap.domains.dns.setHosts")
	if err != nil {
		return err
	}
	params.Set("SLD", sld)
	params.Set("TLD", tld)

	for i, h := range hosts {
		n := strconv.Itoa(i + 1)
		params.Set("HostName"+n, h.Name)
		params.Set("RecordType"+n, h.Type)
		params.Set("Address"+n, h.Address)
		params.Set("TTL"+n, ttlOrDefault(h.TTL))
		if h.Type == "MX" {
			params.Set("MXPref"+n, h.MXPref)
		}
	}

	_, err = c.call(params)
	return err
}

// AddTXTRecord reads existing records, appends the TXT record, and writes all back.
// Namecheap's setHosts replaces all records atomically, so a read-merge-write is required.
func (c *Client) AddTXTRecord(domain, subdomain, value string) error {
	sld, tld, err := SplitDomain(domain)
	if err != nil {
		return err
	}

	hosts, err := c.GetHosts(sld, tld)
	if err != nil {
		return fmt.Errorf("get hosts: %w", err)
	}

	hosts = append(hosts, Host{
		Name:    subdomain,
		Type:    "TXT",
		Address: value,
		TTL:     "60",
	})

	return c.SetHosts(sld, tld, hosts)
}

// RemoveTXTRecord reads existing records, removes the exact matching TXT record,
// and writes all back.
func (c *Client) RemoveTXTRecord(domain, subdomain, value string) error {
	sld, tld, err := SplitDomain(domain)
	if err != nil {
		return err
	}

	hosts, err := c.GetHosts(sld, tld)
	if err != nil {
		return fmt.Errorf("get hosts: %w", err)
	}

	filtered := make([]Host, 0, len(hosts))
	for _, h := range hosts {
		if h.Type == "TXT" && h.Name == subdomain && h.Address == value {
			continue
		}
		filtered = append(filtered, h)
	}

	if len(filtered) == len(hosts) {
		// Nothing to remove — still succeed silently (idempotent cleanup)
		return nil
	}

	return c.SetHosts(sld, tld, filtered)
}

// EnsureCAARecords checks whether CAA records for the given CA already exist
// and adds them if missing. Existing records are not modified.
//
// For Let's Encrypt, ca should be "letsencrypt.org".
// Both "issue" and "issuewild" tags are added.
func (c *Client) EnsureCAARecords(domain, ca string) error {
	sld, tld, err := SplitDomain(domain)
	if err != nil {
		return err
	}

	hosts, err := c.GetHosts(sld, tld)
	if err != nil {
		return fmt.Errorf("get hosts: %w", err)
	}

	hasIssue, hasIssueWild := scanCAARecords(hosts, ca)

	added := 0
	if !hasIssue {
		hosts = append(hosts, Host{
			Name:    "@",
			Type:    "CAA",
			Address: formatCAAValue("issue", ca),
			TTL:     "3600",
		})
		added++
	}
	if !hasIssueWild {
		hosts = append(hosts, Host{
			Name:    "@",
			Type:    "CAA",
			Address: formatCAAValue("issuewild", ca),
			TTL:     "3600",
		})
		added++
	}

	if added == 0 {
		return nil
	}

	return c.SetHosts(sld, tld, hosts)
}

// scanCAARecords checks existing CAA records for the given CA.
// Returns whether "issue" and "issuewild" entries for ca exist.
func scanCAARecords(hosts []Host, ca string) (hasIssue, hasIssueWild bool) {
	for _, h := range hosts {
		if h.Type != "CAA" || h.Name != "@" {
			continue
		}
		if !strings.Contains(h.Address, ca) {
			continue
		}
		// Check issuewild before issue because "issuewild" contains "issue"
		if strings.Contains(h.Address, "issuewild") {
			hasIssueWild = true
		} else if strings.Contains(h.Address, "issue") {
			hasIssue = true
		}
	}
	return
}

// formatCAAValue builds a CAA record value in the form: 0 <tag> "<ca>"
// The quotes are literal, not Go-escaped.
func formatCAAValue(tag, ca string) string {
	return `0 ` + tag + ` "` + ca + `"`
}

// --- IP resolution ---

// PublicIP returns the current public egress IP of the process.
// The result is cached for ipCacheDuration to avoid repeated lookups.
func (c *Client) PublicIP() (string, error) {
	return c.publicIP()
}

func (c *Client) publicIP() (string, error) {
	c.ipMu.Lock()
	defer c.ipMu.Unlock()

	if c.cachedIP != "" && time.Since(c.ipFetchedAt) < ipCacheDuration {
		return c.cachedIP, nil
	}

	req, err := http.NewRequest(http.MethodGet, c.ipEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build ip request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolve public IP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("public IP lookup returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", fmt.Errorf("read public IP response: %w", err)
	}

	ip := strings.TrimSpace(string(body))
	if ip == "" {
		return "", fmt.Errorf("empty public IP response from %s", c.ipEndpoint)
	}

	c.cachedIP = ip
	c.ipFetchedAt = time.Now()
	return ip, nil
}

// --- Internal helpers ---

func (c *Client) baseParams(command string) (url.Values, error) {
	ip, err := c.publicIP()
	if err != nil {
		return nil, fmt.Errorf("get client IP: %w", err)
	}

	p := url.Values{}
	p.Set("ApiUser", c.apiUser)
	p.Set("ApiKey", c.apiKey)
	p.Set("UserName", c.username)
	p.Set("ClientIp", ip)
	p.Set("Command", command)
	return p, nil
}

// call sends the request to the Namecheap API.
// Uses POST because setHosts URLs can exceed reasonable GET length limits.
func (c *Client) call(params url.Values) (*apiResponse, error) {
	req, err := http.NewRequest(http.MethodPost, c.endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("namecheap api request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("namecheap api returned HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var parsed apiResponse
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("parse xml: %w (body: %s)", err, truncate(string(body), 200))
	}

	if parsed.Status != "OK" {
		msgs := make([]string, 0, len(parsed.Errors))
		for _, e := range parsed.Errors {
			msgs = append(msgs, fmt.Sprintf("[%s] %s", e.Number, strings.TrimSpace(e.Message)))
		}
		if len(msgs) == 0 {
			return nil, fmt.Errorf("namecheap api returned status %q without error details", parsed.Status)
		}
		return nil, fmt.Errorf("namecheap api error: %s", strings.Join(msgs, "; "))
	}

	return &parsed, nil
}

// SplitDomain splits a domain name into SLD and TLD.
// Example: "foo.example.com" -> sld="example", tld="com"
func SplitDomain(domain string) (sld, tld string, err error) {
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", "", fmt.Errorf("empty domain")
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid domain: %q", domain)
	}
	tld = parts[len(parts)-1]
	sld = parts[len(parts)-2]
	if sld == "" || tld == "" {
		return "", "", fmt.Errorf("invalid domain: %q", domain)
	}
	return sld, tld, nil
}

func ttlOrDefault(ttl string) string {
	if ttl == "" {
		return "1800"
	}
	return ttl
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
