package ipam

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PhpIPAMAllocator allocates IPs through phpIPAM's REST API.
type PhpIPAMAllocator struct {
	baseURL string
	appID   string
	apiKey  string
	client  *http.Client
}

func NewPhpIPAM(baseURL, appID, apiKey string) *PhpIPAMAllocator {
	return &PhpIPAMAllocator{
		baseURL: strings.TrimRight(baseURL, "/"),
		appID:   appID,
		apiKey:  apiKey,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *PhpIPAMAllocator) Allocate(subnet string) (string, error) {
	subnetID, err := p.lookupSubnetID(subnet)
	if err != nil {
		return "", err
	}
	return p.firstFreeIn(subnetID, subnet)
}

func (p *PhpIPAMAllocator) Release(ip string) error {
	// We don't reserve IPs in phpIPAM ourselves, so there's nothing
	// to give back.
	return nil
}

func (p *PhpIPAMAllocator) lookupSubnetID(subnet string) (string, error) {
	url := fmt.Sprintf("%s/api/%s/subnets/?filter_by=subnet&filter_value=%s",
		p.baseURL, p.appID, subnet)

	body, err := p.get(url)
	if err != nil {
		return "", fmt.Errorf("phpipam: get subnets: %w", err)
	}

	var result struct {
		Success bool `json:"success"`
		Data    []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil || !result.Success || len(result.Data) == 0 {
		return "", fmt.Errorf("phpipam: subnet lookup failed for %s", subnet)
	}
	return result.Data[0].ID, nil
}

func (p *PhpIPAMAllocator) firstFreeIn(subnetID, subnet string) (string, error) {
	url := fmt.Sprintf("%s/api/%s/subnets/%s/first_free/",
		p.baseURL, p.appID, subnetID)

	body, err := p.get(url)
	if err != nil {
		return "", fmt.Errorf("phpipam: first_free: %w", err)
	}

	var result struct {
		Success bool   `json:"success"`
		Data    string `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil || !result.Success {
		return "", fmt.Errorf("phpipam: no free IP in subnet %s", subnet)
	}
	return result.Data, nil
}

func (p *PhpIPAMAllocator) get(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("token", p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
