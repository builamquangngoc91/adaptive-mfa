package controller

import (
	"adaptive-mfa/config"
	"adaptive-mfa/pkg/cache"
	"net/http"
)

type IHackedController interface {
	Disavow(w http.ResponseWriter, r *http.Request)
}

type HackedController struct {
	cfg   *config.Config
	cache cache.ICache
}

func NewHackedController(cfg *config.Config, cache cache.ICache) IHackedController {
	return &HackedController{
		cfg:   cfg,
		cache: cache,
	}
}

func (h *HackedController) Disavow(w http.ResponseWriter, r *http.Request) {
	referenceID := r.URL.Query().Get("ref")

	// TODO: Save the reference ID to the database
	if referenceID == "" {
		http.Error(w, "Reference ID is required", http.StatusBadRequest)
		return
	}

	if err := h.cache.Del(r.Context(), cache.GetMFAReferenceIDKey(referenceID)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
