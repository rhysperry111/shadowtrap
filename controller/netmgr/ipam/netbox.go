package ipam

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// NetBoxAllocator allocates IPs through NetBox's REST API.
type NetBoxAllocator struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewNetBox(baseURL, token string) *NetBoxAllocator {
	return &NetBoxAllocator{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *NetBoxAllocator) Allocate(subnet string) (string, error) {
	url := fmt.Sprintf("%s/api/ipam/ip-addresses/?status=available&parent=%s&limit=1",
		n.baseURL, subnet)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("netbox: build request: %w", err)
	}
	req.Header.Set("Authorization", "Token "+n.token)
	req.Header.Set("Accept", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("netbox: query: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Count   int `json:"count"`
		Results []struct {
			Address string `json:"address"` // "10.0.0.5/24"
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.Count == 0 {
		return "", fmt.Errorf("netbox: no available IP in %s", subnet)
	}

	addr := result.Results[0].Address
	if i := strings.Index(addr, "/"); i != -1 {
		addr = addr[:i]
	}
	return addr, nil
}

func (n *NetBoxAllocator) Release(ip string) error {
	return nil
}
