package provider

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultConnectionStatus = "registered"

type connectionRecord struct {
	ID           string
	Name         string
	Kind         string
	Type         string
	SubType      string
	Metadata     map[string]any
	Status       string
	CredentialID string
	CreatedAt    string
	UpdatedAt    string
}

type connectionCreateRequest struct {
	Name               string         `json:"name"`
	Kind               string         `json:"kind"`
	Type               string         `json:"type"`
	SubType            string         `json:"subType"`
	LegacySubType      string         `json:"sub_type"`
	Metadata           map[string]any `json:"metadata"`
	Status             string         `json:"status"`
	CredentialID       string         `json:"credentialId"`
	LegacyCredentialID string         `json:"credential_id"`
}

type connectionUpdateRequest struct {
	Name               *string         `json:"name"`
	Kind               *string         `json:"kind"`
	Type               *string         `json:"type"`
	SubType            *string         `json:"subType"`
	LegacySubType      *string         `json:"sub_type"`
	Metadata           *map[string]any `json:"metadata"`
	Status             *string         `json:"status"`
	CredentialID       *string         `json:"credentialId"`
	LegacyCredentialID *string         `json:"credential_id"`
}

type connectionStore struct {
	mu    sync.RWMutex
	items map[string]connectionRecord
}

func newConnectionStore() *connectionStore {
	return &connectionStore{
		items: map[string]connectionRecord{},
	}
}

func (s *connectionStore) list(page, pageSize int, search string) []connectionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	needle := strings.ToLower(strings.TrimSpace(search))
	items := make([]connectionRecord, 0, len(s.items))
	for _, item := range s.items {
		if needle != "" && !connectionMatchesSearch(item, needle) {
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
		return []connectionRecord{}
	}

	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}

	return items[start:end]
}

func (s *connectionStore) count(search string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	needle := strings.ToLower(strings.TrimSpace(search))
	total := 0
	for _, item := range s.items {
		if needle != "" && !connectionMatchesSearch(item, needle) {
			continue
		}
		total++
	}

	return total
}

func (s *connectionStore) create(req connectionCreateRequest) (connectionRecord, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	id, err := newConnectionID()
	if err != nil {
		return connectionRecord{}, err
	}

	item := connectionRecord{
		ID:           id,
		Name:         strings.TrimSpace(req.Name),
		Kind:         strings.TrimSpace(req.Kind),
		Type:         strings.TrimSpace(req.Type),
		SubType:      strings.TrimSpace(req.normalizedSubType()),
		Metadata:     cloneMap(req.Metadata),
		Status:       normalizedConnectionStatus(req.Status),
		CredentialID: strings.TrimSpace(req.normalizedCredentialID()),
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.items[item.ID] = item
	return item, nil
}

func (s *connectionStore) get(id string) (connectionRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	item, ok := s.items[id]
	return item, ok
}

func (s *connectionStore) update(id string, req connectionUpdateRequest) (connectionRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[id]
	if !ok {
		return connectionRecord{}, false
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
	if req.Status != nil {
		item.Status = normalizedConnectionStatus(*req.Status)
	}
	if credentialID, exists := req.normalizedCredentialID(); exists {
		item.CredentialID = strings.TrimSpace(credentialID)
	}
	item.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	s.items[id] = item
	return item, true
}

func (s *connectionStore) delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.items[id]; !ok {
		return false
	}

	delete(s.items, id)
	return true
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleListConnections(w, r)
	case http.MethodPost:
		s.handleCreateConnection(w, r)
	default:
		w.Header().Set("Allow", strings.Join([]string{http.MethodGet, http.MethodPost}, ", "))
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleConnectionByID(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing connection id"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		item, ok := s.connections.get(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection not found"})
			return
		}
		writeJSON(w, http.StatusOK, item.response())
	case http.MethodPut:
		s.handleUpdateConnection(w, r, id)
	case http.MethodDelete:
		if !s.connections.delete(id) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection not found"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", strings.Join([]string{http.MethodGet, http.MethodPut, http.MethodDelete}, ", "))
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleListConnections(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	page := parsePositiveInt(query.Get("page"), 1)
	pageSize := parsePositiveInt(firstNonEmpty(query.Get("pageSize"), query.Get("pagesize")), 0)
	search := firstNonEmpty(query.Get("search"), query.Get("q"))

	items := s.connections.list(page, pageSize, search)
	total := s.connections.count(search)
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
		"connections": responseItems,
	})
}

func (s *Server) handleCreateConnection(w http.ResponseWriter, r *http.Request) {
	var req connectionCreateRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := validateCreateConnection(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	item, err := s.connections.create(req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to create connection"})
		return
	}

	w.Header().Set("Location", "/api/connections/"+item.ID)
	writeJSON(w, http.StatusCreated, item.response())
}

func (s *Server) handleUpdateConnection(w http.ResponseWriter, r *http.Request, id string) {
	var req connectionUpdateRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := validateUpdateConnection(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	item, ok := s.connections.update(id, req)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection not found"})
		return
	}

	writeJSON(w, http.StatusOK, item.response())
}

func (c connectionCreateRequest) normalizedSubType() string {
	if strings.TrimSpace(c.SubType) != "" {
		return c.SubType
	}
	return c.LegacySubType
}

func (c connectionCreateRequest) normalizedCredentialID() string {
	if strings.TrimSpace(c.CredentialID) != "" {
		return c.CredentialID
	}
	return c.LegacyCredentialID
}

func (c connectionUpdateRequest) normalizedSubType() (string, bool) {
	if c.SubType != nil {
		return *c.SubType, true
	}
	if c.LegacySubType != nil {
		return *c.LegacySubType, true
	}
	return "", false
}

func (c connectionUpdateRequest) normalizedCredentialID() (string, bool) {
	if c.CredentialID != nil {
		return *c.CredentialID, true
	}
	if c.LegacyCredentialID != nil {
		return *c.LegacyCredentialID, true
	}
	return "", false
}

func (c connectionRecord) response() map[string]any {
	payload := map[string]any{
		"id":         c.ID,
		"name":       c.Name,
		"kind":       c.Kind,
		"type":       c.Type,
		"metadata":   cloneMap(c.Metadata),
		"status":     c.Status,
		"createdAt":  c.CreatedAt,
		"created_at": c.CreatedAt,
		"updatedAt":  c.UpdatedAt,
		"updated_at": c.UpdatedAt,
	}

	if c.SubType != "" {
		payload["subType"] = c.SubType
		payload["sub_type"] = c.SubType
	}
	if c.CredentialID != "" {
		payload["credentialId"] = c.CredentialID
		payload["credential_id"] = c.CredentialID
	}

	return payload
}

func validateCreateConnection(req connectionCreateRequest) error {
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

func validateUpdateConnection(req connectionUpdateRequest) error {
	if req.Name != nil && strings.TrimSpace(*req.Name) == "" {
		return errors.New("name cannot be empty")
	}
	if req.Kind != nil && strings.TrimSpace(*req.Kind) == "" {
		return errors.New("kind cannot be empty")
	}
	if req.Type != nil && strings.TrimSpace(*req.Type) == "" {
		return errors.New("type cannot be empty")
	}
	if req.Status != nil && strings.TrimSpace(*req.Status) == "" {
		return errors.New("status cannot be empty")
	}

	return nil
}

func decodeJSONBody(body io.ReadCloser, target any) error {
	defer body.Close()

	decoder := json.NewDecoder(body)
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid json body")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single json object")
	}

	return nil
}

func connectionMatchesSearch(item connectionRecord, needle string) bool {
	fields := []string{item.ID, item.Name, item.Kind, item.Type, item.SubType, item.Status}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), needle) {
			return true
		}
	}

	for key, value := range item.Metadata {
		if strings.Contains(strings.ToLower(key), needle) {
			return true
		}
		if strings.Contains(strings.ToLower(fmt.Sprint(value)), needle) {
			return true
		}
	}

	return false
}

func normalizedConnectionStatus(status string) string {
	if strings.TrimSpace(status) == "" {
		return defaultConnectionStatus
	}

	return strings.ToLower(strings.TrimSpace(status))
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}

	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}

	return output
}

func parsePositiveInt(value string, fallback int) int {
	if strings.TrimSpace(value) == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return fallback
	}

	return parsed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}

	return ""
}

func newConnectionID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80

	encoded := hex.EncodeToString(buf)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[0:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32]), nil
}
