package provider

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type environmentRecord struct {
	ID             string
	Name           string
	Description    string
	OrganizationID string
	Metadata       map[string]any
	CreatedAt      string
	UpdatedAt      string
}

type environmentCreateRequest struct {
	Name               string         `json:"name"`
	Description        string         `json:"description"`
	OrganizationID     string         `json:"organizationId"`
	LegacyOrganization string         `json:"organization_id"`
	Metadata           map[string]any `json:"metadata"`
}

type environmentStore struct {
	mu    sync.RWMutex
	items map[string]environmentRecord
}

func newEnvironmentStore() *environmentStore {
	now := time.Now().UTC().Format(time.RFC3339)
	defaultEnvironment := environmentRecord{
		ID:             "6f820d4d-750a-49d1-b67e-6f337f15af06",
		Name:           "Default Environment",
		Description:    "Starter environment payload for Meshery Remote Provider development.",
		OrganizationID: defaultOrganizationID,
		Metadata: map[string]any{
			"workspaceId": defaultWorkspaceID,
			"provider":    "remote",
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	return &environmentStore{
		items: map[string]environmentRecord{
			defaultEnvironment.ID: defaultEnvironment,
		},
	}
}

func (s *environmentStore) list() []environmentRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]environmentRecord, 0, len(s.items))
	for _, item := range s.items {
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt < items[j].CreatedAt
	})

	return items
}

func (s *environmentStore) get(id string) (environmentRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	item, ok := s.items[id]
	return item, ok
}

func (s *environmentStore) create(req environmentCreateRequest) (environmentRecord, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	id, err := newResourceID()
	if err != nil {
		return environmentRecord{}, err
	}

	item := environmentRecord{
		ID:             id,
		Name:           strings.TrimSpace(req.Name),
		Description:    strings.TrimSpace(req.Description),
		OrganizationID: strings.TrimSpace(req.normalizedOrganizationID()),
		Metadata:       cloneMap(req.Metadata),
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.items[item.ID] = item
	return item, nil
}

func (s *Server) handleEnvironments(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		items := s.environments.list()
		responseItems := make([]map[string]any, 0, len(items))
		for _, item := range items {
			responseItems = append(responseItems, item.response())
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"page":         1,
			"pageSize":     len(responseItems),
			"page_size":    len(responseItems),
			"totalCount":   len(responseItems),
			"total_count":  len(responseItems),
			"data":         responseItems,
			"environments": responseItems,
		})
	case http.MethodPost:
		var req environmentCreateRequest
		if err := decodeJSONBody(r.Body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		if err := validateCreateEnvironment(req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		item, err := s.environments.create(req)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to create environment"})
			return
		}

		w.Header().Set("Location", "/api/environments/"+item.ID)
		writeJSON(w, http.StatusCreated, item.response())
	default:
		w.Header().Set("Allow", strings.Join([]string{http.MethodGet, http.MethodPost}, ", "))
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleEnvironmentByID(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing environment id"})
		return
	}

	item, ok := s.environments.get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "environment not found"})
		return
	}

	writeJSON(w, http.StatusOK, item.response())
}

func (e environmentRecord) response() map[string]any {
	payload := map[string]any{
		"id":              e.ID,
		"name":            e.Name,
		"description":     e.Description,
		"organizationId":  e.OrganizationID,
		"organization_id": e.OrganizationID,
		"metadata":        cloneMap(e.Metadata),
		"createdAt":       e.CreatedAt,
		"created_at":      e.CreatedAt,
		"updatedAt":       e.UpdatedAt,
		"updated_at":      e.UpdatedAt,
	}

	return payload
}

func (e environmentCreateRequest) normalizedOrganizationID() string {
	if strings.TrimSpace(e.OrganizationID) != "" {
		return e.OrganizationID
	}

	if strings.TrimSpace(e.LegacyOrganization) != "" {
		return e.LegacyOrganization
	}

	return defaultOrganizationID
}

func validateCreateEnvironment(req environmentCreateRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return errors.New("name is required")
	}

	return nil
}
