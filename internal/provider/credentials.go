package provider

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type credentialRecord struct {
	ID        string
	Name      string
	Kind      string
	Type      string
	SubType   string
	Metadata  map[string]any
	Secret    map[string]any
	CreatedAt string
	UpdatedAt string
}

type credentialCreateRequest struct {
	Name          string         `json:"name"`
	Kind          string         `json:"kind"`
	Type          string         `json:"type"`
	SubType       string         `json:"subType"`
	LegacySubType string         `json:"sub_type"`
	Metadata      map[string]any `json:"metadata"`
	Secret        map[string]any `json:"secret"`
}

type credentialUpdateRequest struct {
	Name          *string         `json:"name"`
	Kind          *string         `json:"kind"`
	Type          *string         `json:"type"`
	SubType       *string         `json:"subType"`
	LegacySubType *string         `json:"sub_type"`
	Metadata      *map[string]any `json:"metadata"`
	Secret        *map[string]any `json:"secret"`
}

type credentialStore struct {
	mu    sync.RWMutex
	items map[string]credentialRecord
}

func newCredentialStore() *credentialStore {
	return &credentialStore{
		items: map[string]credentialRecord{},
	}
}

func (s *credentialStore) list() []credentialRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]credentialRecord, 0, len(s.items))
	for _, item := range s.items {
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt < items[j].CreatedAt
	})

	return items
}

func (s *credentialStore) create(req credentialCreateRequest) (credentialRecord, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	id, err := newResourceID()
	if err != nil {
		return credentialRecord{}, err
	}

	item := credentialRecord{
		ID:        id,
		Name:      strings.TrimSpace(req.Name),
		Kind:      strings.TrimSpace(req.Kind),
		Type:      strings.TrimSpace(req.Type),
		SubType:   strings.TrimSpace(req.normalizedSubType()),
		Metadata:  cloneMap(req.Metadata),
		Secret:    cloneMap(req.Secret),
		CreatedAt: now,
		UpdatedAt: now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.items[item.ID] = item
	return item, nil
}

func (s *credentialStore) get(id string) (credentialRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	item, ok := s.items[id]
	return item, ok
}

func (s *credentialStore) update(id string, req credentialUpdateRequest) (credentialRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[id]
	if !ok {
		return credentialRecord{}, false
	}

	if req.Name != nil {
		item.Name = strings.TrimSpace(*req.Name)
	}
	if req.Kind != nil {
		item.Kind = strings.TrimSpace(*req.Kind)
	}
	if req.Type != nil {
		item.Type = strings.TrimSpace(*req.Type)
	}
	if subType, exists := req.normalizedSubType(); exists {
		item.SubType = strings.TrimSpace(subType)
	}
	if req.Metadata != nil {
		item.Metadata = cloneMap(*req.Metadata)
	}
	if req.Secret != nil {
		item.Secret = cloneMap(*req.Secret)
	}
	item.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	s.items[id] = item
	return item, true
}

func (s *credentialStore) delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.items[id]; !ok {
		return false
	}

	delete(s.items, id)
	return true
}

func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		items := s.credentials.list()
		responseItems := make([]map[string]any, 0, len(items))
		for _, item := range items {
			responseItems = append(responseItems, item.response())
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"page":        1,
			"pageSize":    len(responseItems),
			"totalCount":  len(responseItems),
			"data":        responseItems,
			"credentials": responseItems,
		})
	case http.MethodPost:
		var req credentialCreateRequest
		if err := decodeJSONBody(r.Body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		if err := validateCreateCredential(req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		item, err := s.credentials.create(req)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to create credential"})
			return
		}

		w.Header().Set("Location", "/api/credentials/"+item.ID)
		writeJSON(w, http.StatusCreated, item.response())
	default:
		w.Header().Set("Allow", strings.Join([]string{http.MethodGet, http.MethodPost}, ", "))
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleCredentialByID(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing credential id"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		item, ok := s.credentials.get(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "credential not found"})
			return
		}

		writeJSON(w, http.StatusOK, item.response())
	case http.MethodPut:
		var req credentialUpdateRequest
		if err := decodeJSONBody(r.Body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		if err := validateUpdateCredential(req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		item, ok := s.credentials.update(id, req)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "credential not found"})
			return
		}

		writeJSON(w, http.StatusOK, item.response())
	case http.MethodDelete:
		if !s.credentials.delete(id) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "credential not found"})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", strings.Join([]string{http.MethodGet, http.MethodPut, http.MethodDelete}, ", "))
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (c credentialCreateRequest) normalizedSubType() string {
	if strings.TrimSpace(c.SubType) != "" {
		return c.SubType
	}

	return c.LegacySubType
}

func (c credentialUpdateRequest) normalizedSubType() (string, bool) {
	if c.SubType != nil {
		return *c.SubType, true
	}
	if c.LegacySubType != nil {
		return *c.LegacySubType, true
	}

	return "", false
}

func (c credentialRecord) response() map[string]any {
	payload := map[string]any{
		"id":         c.ID,
		"name":       c.Name,
		"kind":       c.Kind,
		"type":       c.Type,
		"metadata":   cloneMap(c.Metadata),
		"secret":     cloneMap(c.Secret),
		"createdAt":  c.CreatedAt,
		"created_at": c.CreatedAt,
		"updatedAt":  c.UpdatedAt,
		"updated_at": c.UpdatedAt,
	}

	if c.SubType != "" {
		payload["subType"] = c.SubType
		payload["sub_type"] = c.SubType
	}

	return payload
}

func validateCreateCredential(req credentialCreateRequest) error {
	switch {
	case strings.TrimSpace(req.Name) == "":
		return errors.New("name is required")
	case strings.TrimSpace(req.Kind) == "":
		return errors.New("kind is required")
	case strings.TrimSpace(req.Type) == "":
		return errors.New("type is required")
	default:
		return nil
	}
}

func validateUpdateCredential(req credentialUpdateRequest) error {
	if req.Name != nil && strings.TrimSpace(*req.Name) == "" {
		return errors.New("name cannot be empty")
	}
	if req.Kind != nil && strings.TrimSpace(*req.Kind) == "" {
		return errors.New("kind cannot be empty")
	}
	if req.Type != nil && strings.TrimSpace(*req.Type) == "" {
		return errors.New("type cannot be empty")
	}

	return nil
}
