package provider

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type organizationRecord struct {
	ID          string
	Name        string
	Country     string
	Region      string
	Description string
	Owner       string
	Metadata    map[string]any
	Domain      string
	CreatedAt   string
	UpdatedAt   string
	DeletedAt   string
}

type organizationCreateRequest struct {
	Name        string         `json:"name"`
	Country     string         `json:"country"`
	Region      string         `json:"region"`
	Description string         `json:"description"`
	Owner       string         `json:"owner"`
	Metadata    map[string]any `json:"metadata"`
	Domain      string         `json:"domain"`
}

type organizationUpdateRequest struct {
	Name        *string         `json:"name"`
	Country     *string         `json:"country"`
	Region      *string         `json:"region"`
	Description *string         `json:"description"`
	Owner       *string         `json:"owner"`
	Metadata    *map[string]any `json:"metadata"`
	Domain      *string         `json:"domain"`
}

type organizationStore struct {
	mu    sync.RWMutex
	items map[string]organizationRecord
}

func newOrganizationStore() *organizationStore {
	return &organizationStore{
		items: map[string]organizationRecord{},
	}
}

func (s *organizationStore) list(page, pageSize int, search string) []organizationRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	needle := strings.ToLower(strings.TrimSpace(search))
	items := make([]organizationRecord, 0, len(s.items))
	for _, item := range s.items {
		if item.DeletedAt != "" {
			continue
		}
		if needle != "" && !organizationMatchesSearch(item, needle) {
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
		return []organizationRecord{}
	}

	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}

	return items[start:end]
}

func (s *organizationStore) count(search string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	needle := strings.ToLower(strings.TrimSpace(search))
	total := 0
	for _, item := range s.items {
		if item.DeletedAt != "" {
			continue
		}
		if needle != "" && !organizationMatchesSearch(item, needle) {
			continue
		}
		total++
	}

	return total
}

func (s *organizationStore) create(req organizationCreateRequest) (organizationRecord, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	id, err := newResourceID()
	if err != nil {
		return organizationRecord{}, err
	}

	item := organizationRecord{
		ID:          id,
		Name:        strings.TrimSpace(req.Name),
		Country:     strings.TrimSpace(req.Country),
		Region:      strings.TrimSpace(req.Region),
		Description: strings.TrimSpace(req.Description),
		Owner:       strings.TrimSpace(req.Owner),
		Metadata:    cloneMap(req.Metadata),
		Domain:      strings.TrimSpace(req.Domain),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.items[item.ID] = item
	return item, nil
}

func (s *organizationStore) get(id string) (organizationRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	item, ok := s.items[id]
	if !ok || item.DeletedAt != "" {
		return organizationRecord{}, false
	}
	return item, true
}

func (s *organizationStore) update(id string, req organizationUpdateRequest) (organizationRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[id]
	if !ok || item.DeletedAt != "" {
		return organizationRecord{}, false
	}

	if req.Name != nil {
		item.Name = strings.TrimSpace(*req.Name)
	}
	if req.Country != nil {
		item.Country = strings.TrimSpace(*req.Country)
	}
	if req.Region != nil {
		item.Region = strings.TrimSpace(*req.Region)
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
	if req.Domain != nil {
		item.Domain = strings.TrimSpace(*req.Domain)
	}
	item.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	s.items[id] = item
	return item, true
}

func (s *organizationStore) delete(id string) bool {
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

func (s *Server) handleOrganizations(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleListOrganizations(w, r)
	case http.MethodPost:
		s.handleCreateOrganization(w, r)
	default:
		w.Header().Set("Allow", strings.Join([]string{http.MethodGet, http.MethodPost}, ", "))
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleOrganizationByID(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing organization id"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		item, ok := s.organizations.get(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "organization not found"})
			return
		}
		writeJSON(w, http.StatusOK, item.response())
	case http.MethodPut:
		s.handleUpdateOrganization(w, r, id)
	case http.MethodDelete:
		if !s.organizations.delete(id) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "organization not found"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", strings.Join([]string{http.MethodGet, http.MethodPut, http.MethodDelete}, ", "))
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleListOrganizations(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	page := parsePositiveInt(query.Get("page"), 1)
	pageSize := parsePositiveInt(firstNonEmpty(query.Get("pageSize"), query.Get("pagesize")), 0)
	search := firstNonEmpty(query.Get("search"), query.Get("q"))

	items := s.organizations.list(page, pageSize, search)
	total := s.organizations.count(search)
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

func (s *Server) handleCreateOrganization(w http.ResponseWriter, r *http.Request) {
	var req organizationCreateRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := validateCreateOrganization(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	item, err := s.organizations.create(req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to create organization"})
		return
	}

	w.Header().Set("Location", "/api/organizations/"+item.ID)
	writeJSON(w, http.StatusCreated, item.response())
}

func (s *Server) handleUpdateOrganization(w http.ResponseWriter, r *http.Request, id string) {
	var req organizationUpdateRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := validateUpdateOrganization(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	item, ok := s.organizations.update(id, req)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "organization not found"})
		return
	}

	writeJSON(w, http.StatusOK, item.response())
}

func (o organizationRecord) response() map[string]any {
	payload := map[string]any{
		"id":          o.ID,
		"name":        o.Name,
		"country":     o.Country,
		"region":      o.Region,
		"description": o.Description,
		"owner":       o.Owner,
		"metadata":    cloneMap(o.Metadata),
		"createdAt":   o.CreatedAt,
		"created_at":  o.CreatedAt,
		"updatedAt":   o.UpdatedAt,
		"updated_at":  o.UpdatedAt,
	}

	if o.Domain != "" {
		payload["domain"] = o.Domain
	}
	if o.DeletedAt != "" {
		payload["deletedAt"] = o.DeletedAt
		payload["deleted_at"] = o.DeletedAt
	}

	return payload
}

func validateCreateOrganization(req organizationCreateRequest) error {
	switch {
	case strings.TrimSpace(req.Name) == "":
		return errors.New("name is required")
	case strings.TrimSpace(req.Country) == "":
		return errors.New("country is required")
	case strings.TrimSpace(req.Region) == "":
		return errors.New("region is required")
	case strings.TrimSpace(req.Description) == "":
		return errors.New("description is required")
	case strings.TrimSpace(req.Owner) == "":
		return errors.New("owner is required")
	case req.Metadata == nil:
		return errors.New("metadata is required")
	default:
		return nil
	}
}

func validateUpdateOrganization(req organizationUpdateRequest) error {
	if req.Name != nil && strings.TrimSpace(*req.Name) == "" {
		return errors.New("name cannot be empty")
	}
	if req.Country != nil && strings.TrimSpace(*req.Country) == "" {
		return errors.New("country cannot be empty")
	}
	if req.Region != nil && strings.TrimSpace(*req.Region) == "" {
		return errors.New("region cannot be empty")
	}
	if req.Description != nil && strings.TrimSpace(*req.Description) == "" {
		return errors.New("description cannot be empty")
	}
	if req.Owner != nil && strings.TrimSpace(*req.Owner) == "" {
		return errors.New("owner cannot be empty")
	}

	return nil
}

func organizationMatchesSearch(item organizationRecord, needle string) bool {
	fields := []string{item.ID, item.Name, item.Country, item.Region, item.Description, item.Owner, item.Domain}
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
