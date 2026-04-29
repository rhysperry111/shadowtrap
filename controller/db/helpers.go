package db

import (
	"encoding/json"
	"fmt"
)

// ImageFeature is the element type stored in Image.Features (JSONB).
type ImageFeature struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func ParseFeatures(raw json.RawMessage) ([]ImageFeature, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var f []ImageFeature
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("db: parse features: %w", err)
	}
	return f, nil
}

func PotID(deployment, network, image string, discriminator int) string {
	return fmt.Sprintf("%s@%s@%s@%d", deployment, network, image, discriminator)
}
