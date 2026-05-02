package api

import (
	"net/http"

	"shadowtrap/controller/db"
)

type imageFeatureJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type imageJSON struct {
	ID       string             `json:"id"`
	Base     string             `json:"base"`
	Version  string             `json:"version"`
	OS       string             `json:"os"`
	Features []imageFeatureJSON `json:"features,omitempty"`
}

func imageToJSON(image db.Image) imageJSON {
	features, _ := db.ParseFeatures(image.Features)

	out := make([]imageFeatureJSON, len(features))
	for i, f := range features {
		out[i] = imageFeatureJSON{Name: f.Name, Version: f.Version}
	}

	return imageJSON{
		ID:       image.ID,
		Base:     image.Base,
		Version:  image.Version,
		OS:       image.Os,
		Features: out,
	}
}

func (h *Handler) getImages(w http.ResponseWriter, r *http.Request) {
	images, err := h.queries.ListImages(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ERR_INTERNAL", err.Error())
		return
	}

	out := make([]imageJSON, len(images))
	for i, image := range images {
		out[i] = imageToJSON(image)
	}
	writeJSON(w, http.StatusOK, map[string]any{"images": out})
}

func (h *Handler) getImage(w http.ResponseWriter, r *http.Request) {
	image, err := h.queries.GetImage(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "ERR_NOT_FOUND", "image not found")
		return
	}
	writeJSON(w, http.StatusOK, imageToJSON(image))
}
