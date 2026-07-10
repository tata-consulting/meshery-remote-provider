package provider

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type workspaceRecord struct {
	ID             string
	Name           string
	Description    string
	OrganizationID string
	Owner          string
	Metadata       map[string]any
	CreatedAt      string
	UpdatedAt      string
	DeletedAt      string
}

type workspaceCreateRequest struct {
	Name           string         `json:"name"`
	Description    string         `json:"description"`
	OrganizationID string         `json:"organizationId"`
	Owner          string         `json:"owner"`
	Metadata       map[string]any `json:"metadata"`
}

type workspaceUpdateRequest struct {
	Name           *string         `json:"name"`
	Description    *string         `json:"description"`
	Owner          *string         `json:"owner"`
	Metadata       *map[string]any `json:"metadata"`
}

type workspaceStore struct {
	mu    sync.RWMutex
	items map[string]workspaceRecord
}

func newWorkspaceStore() *workspaceStore {
	return &workspaceStore{
		items: map[string]workspaceRecord{},
	}
}

func (s *workspaceStore) list(page, pageSize int, search string) []workspaceRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	needle := strings.ToLower(strings.TrimSpace(search))
	items := make([]workspaceRecord, 0, len(s.items))
	for _, item := range s.items {
		if item.DeletedAt != "" {
			continue
		}
		if needle != "" && !workspaceMatchesSearch(item, needle) {
			continue
		}
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt < items[j].CreatedAt
	})

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		return items
	}

	start := (page - 1) * pageSize
	if start >= len(items) {
		return []workspaceRecord{}
	}

	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}

	return items[start:end]
}

func (s *workspaceStore) count(search string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	needle := strings.ToLower(strings.TrimSpace(search))
	total := 0
	for _, item := range s.items {
		if item.DeletedAt != "" {
			continue
		}
		if needle != "" && !workspaceMatchesSearch(item, needle) {
			continue
		}
		total++
	}

	return total
}

func (s *workspaceStore) create(req workspaceCreateRequest) (workspaceRecord, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	id, err := newResourceID()
	if err != nil {
		return workspaceRecord{}, err
	}

	item := workspaceRecord{
		ID:             id,
		Name:           strings.TrimSpace(req.Name),
		Description:    strings.TrimSpace(req.Description),
		OrganizationID: strings.TrimSpace(req.OrganizationID),
		Owner:          strings.TrimSpace(req.Owner),
		Metadata:       cloneMap(req.Metadata),
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.items[item.ID] = item
	return item, nil
}

func (s *workspaceStore) get(id string) (workspaceRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	item, ok := s.items[id]
	if !ok || item.DeletedAt != "" {
		return workspaceRecord{}, false
	}
	return item, true
}

func (s *workspaceStore) update(id string, req workspaceUpdateRequest) (workspaceRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[id]
	if !ok || item.DeletedAt != "" {
		return workspaceRecord{}, false
	}

	if req.Name != nil {
		item.Name = strings.TrimSpace(*req.Name)
	}
	if req.Description != nil {
		item.Description = strings.TrimSpace(*req.Description)
	}
	if req.Owner != nil {
		item.Owner = strings.TrimSpace(*req.Owner)
	}
	if req.Metadata != nil {
		item.Metadata = cloneMap(*req.Metadata)
	}
	item.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	s.items[id] = item
	return item, true
}

func (s *workspaceStore) delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[id]
	if !ok || item.DeletedAt != "" {
		return false
	}

	item.DeletedAt = time.Now().UTC().Format(time.RFC3339)
	s.items[id] = item
	return true
}

func (s *Server) handleWorkspaces(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleListWorkspaces(w, r)
	case http.MethodPost:
		s.handleCreateWorkspace(w, r)
	default:
		w.Header().Set("Allow", strings.Join([]string{http.MethodGet, http.MethodPost}, ", "))
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleWorkspaceByID(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing workspace id"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		item, ok := s.workspaces.get(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "workspace not found"})
			return
		}
		writeJSON(w, http.StatusOK, item.response())
	case http.MethodPut:
		s.handleUpdateWorkspace(w, r, id)
	case http.MethodDelete:
		if !s.workspaces.delete(id) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "workspace not found"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", strings.Join([]string{http.MethodGet, http.MethodPut, http.MethodDelete}, ", "))
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleListWorkspaces(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	page := parsePositiveInt(query.Get("page"), 1)
	pageSize := parsePositiveInt(firstNonEmpty(query.Get("pageSize"), query.Get("pagesize")), 0)
	search := firstNonEmpty(query.Get("search"), query.Get("q"))

	items := s.workspaces.list(page, pageSize, search)
	total := s.workspaces.count(search)
	responsePageSize := pageSize
	if pageSize == 0 {
		responsePageSize = len(items)
	}

	responseItems := make([]map[string]any, 0, len(items))
	for _, item := range items {
		responseItems = append(responseItems, item.response())
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"page":        page,
		"pageSize":    responsePageSize,
		"page_size":   responsePageSize,
		"totalCount":  total,
		"total_count": total,
		"data":        responseItems,
	})
}

func (s *Server) handleCreateWorkspace(w http.ResponseWriter, r *http.Request) {
	var req workspaceCreateRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := validateCreateWorkspace(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	item, err := s.workspaces.create(req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to create workspace"})
		return
	}

	w.Header().Set("Location", "/api/workspaces/"+item.ID)
	writeJSON(w, http.StatusCreated, item.response())
}

func (s *Server) handleUpdateWorkspace(w http.ResponseWriter, r *http.Request, id string) {
	var req workspaceUpdateRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := validateUpdateWorkspace(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	item, ok := s.workspaces.update(id, req)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "workspace not found"})
		return
	}

	writeJSON(w, http.StatusOK, item.response())
}

func (w workspaceRecord) response() map[string]any {
	payload := map[string]any{
		"id":             w.ID,
		"name":           w.Name,
		"organizationId": w.OrganizationID,
		"createdAt":      w.CreatedAt,
		"created_at":     w.CreatedAt,
		"updatedAt":      w.UpdatedAt,
		"updated_at":     w.UpdatedAt,
	}

	if w.Description != "" {
		payload["description"] = w.Description
	}
	if w.Owner != "" {
		payload["owner"] = w.Owner
	}
	if len(w.Metadata) > 0 {
		payload["metadata"] = cloneMap(w.Metadata)
	}
	if w.DeletedAt != "" {
		payload["deletedAt"] = w.DeletedAt
		payload["deleted_at"] = w.DeletedAt
	}

	return payload
}

func validateCreateWorkspace(req workspaceCreateRequest) error {
	switch {
	case strings.TrimSpace(req.Name) == "":
		return errors.New("name is required")
	case strings.TrimSpace(req.OrganizationID) == "":
		return errors.New("organizationId is required")
	default:
		return nil
	}
}

func validateUpdateWorkspace(req workspaceUpdateRequest) error {
	if req.Name != nil && strings.TrimSpace(*req.Name) == "" {
		return errors.New("name cannot be empty")
	}
	if req.Description != nil && strings.TrimSpace(*req.Description) == "" {
		return errors.New("description cannot be empty")
	}
	if req.Owner != nil && strings.TrimSpace(*req.Owner) == "" {
		return errors.New("owner cannot be empty")
	}

	return nil
}

func workspaceMatchesSearch(item workspaceRecord, needle string) bool {
	fields := []string{item.ID, item.Name, item.Description, item.OrganizationID, item.Owner}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), needle) {
			return true
		}
	}

	for key, value := range item.Metadata {
		if strings.Contains(strings.ToLower(key), needle) {
			return true
		}
		if strings.Contains(strings.ToLower(stringifyValue(value)), needle) {
			return true
		}
	}

	return false
}

func stringifyValue(value any) string {
	if v, ok := value.(string); ok {
		return v
	}
	return ""
}
