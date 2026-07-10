package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID               string            `json:"id"`
	Provider         string            `json:"provider"`
	Email            string            `json:"email"`
	FirstName        string            `json:"firstName"`
	LastName         string            `json:"lastName"`
	AvatarURL        string            `json:"avatarUrl,omitempty"`
	Status           string            `json:"status"`
	Bio              string            `json:"bio,omitempty"`
	Country          map[string]any    `json:"country,omitempty"`
	Region           map[string]any    `json:"region,omitempty"`
	Preferences      map[string]any    `json:"preferences,omitempty"`
	AcceptedTermsAt  *time.Time        `json:"acceptedTermsAt,omitempty"`
	FirstLoginTime   *time.Time        `json:"firstLoginTime,omitempty"`
	LastLoginTime    *time.Time        `json:"lastLoginTime,omitempty"`
	CreatedAt        time.Time         `json:"createdAt"`
	UpdatedAt        time.Time         `json:"updatedAt"`
	DeletedAt        *time.Time        `json:"deletedAt,omitempty"`
	RoleNames        []string          `json:"roleNames,omitempty"`
	Teams            map[string]any    `json:"teams,omitempty"`
}

// UserStore manages user persistence
type UserStore struct {
	mu    sync.RWMutex
	users map[string]*User
}

// NewUserStore creates a new user store
func NewUserStore() *UserStore {
	return &UserStore{
		users: make(map[string]*User),
	}
}

// CreateUser creates a new user
func (s *UserStore) CreateUser(user *User) (*User, error) {
	if user == nil {
		return nil, errors.New("user cannot be nil")
	}

	if err := validateUser(user); err != nil {
		return nil, err
	}

	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	now := time.Now().UTC()
	user.CreatedAt = now
	user.UpdatedAt = now

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.ID]; exists {
		return nil, fmt.Errorf("user with id %s already exists", user.ID)
	}

	s.users[user.ID] = user
	return user, nil
}

// GetUser retrieves a user by ID (excluding soft-deleted)
func (s *UserStore) GetUser(id string) (*User, error) {
	if id == "" {
		return nil, errors.New("user id cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists || user.DeletedAt != nil {
		return nil, fmt.Errorf("user with id %s not found", id)
	}

	return user, nil
}

// ListUsers retrieves all non-deleted users with pagination and search
func (s *UserStore) ListUsers(page, pageSize int, search string) ([]User, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []User
	for _, user := range s.users {
		if user.DeletedAt != nil {
			continue
		}

		if search != "" {
			lowerSearch := strings.ToLower(search)
			if !strings.Contains(strings.ToLower(user.Email), lowerSearch) &&
				!strings.Contains(strings.ToLower(user.FirstName), lowerSearch) &&
				!strings.Contains(strings.ToLower(user.LastName), lowerSearch) {
				continue
			}
		}

		filtered = append(filtered, *user)
	}

	totalCount := len(filtered)
	start := (page - 1) * pageSize
	end := start + pageSize
	if end > totalCount {
		end = totalCount
	}

	if start >= totalCount {
		return []User{}, totalCount, nil
	}

	return filtered[start:end], totalCount, nil
}

// UpdateUser updates a user
func (s *UserStore) UpdateUser(id string, updates map[string]any) (*User, error) {
	if id == "" {
		return nil, errors.New("user id cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[id]
	if !exists || user.DeletedAt != nil {
		return nil, fmt.Errorf("user with id %s not found", id)
	}

	// Apply updates
	if provider, ok := updates["provider"].(string); ok && provider != "" {
		user.Provider = provider
	}
	if email, ok := updates["email"].(string); ok && email != "" {
		user.Email = email
	}
	if firstName, ok := updates["firstName"].(string); ok && firstName != "" {
		user.FirstName = firstName
	}
	if lastName, ok := updates["lastName"].(string); ok && lastName != "" {
		user.LastName = lastName
	}
	if avatarURL, ok := updates["avatarUrl"].(string); ok {
		user.AvatarURL = avatarURL
	}
	if status, ok := updates["status"].(string); ok && status != "" {
		if !isValidStatus(status) {
			return nil, fmt.Errorf("invalid status: %s", status)
		}
		user.Status = status
	}
	if bio, ok := updates["bio"].(string); ok {
		user.Bio = bio
	}
	if country, ok := updates["country"].(map[string]any); ok {
		user.Country = country
	}
	if region, ok := updates["region"].(map[string]any); ok {
		user.Region = region
	}
	if preferences, ok := updates["preferences"].(map[string]any); ok {
		user.Preferences = preferences
	}
	if roleNames, ok := updates["roleNames"].([]any); ok {
		roles := make([]string, len(roleNames))
		for i, r := range roleNames {
			roles[i] = r.(string)
		}
		user.RoleNames = roles
	}
	if teams, ok := updates["teams"].(map[string]any); ok {
		user.Teams = teams
	}

	user.UpdatedAt = time.Now().UTC()
	return user, nil
}

// DeleteUser soft-deletes a user
func (s *UserStore) DeleteUser(id string) error {
	if id == "" {
		return errors.New("user id cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[id]
	if !exists || user.DeletedAt != nil {
		return fmt.Errorf("user with id %s not found", id)
	}

	now := time.Now().UTC()
	user.DeletedAt = &now
	user.UpdatedAt = now

	return nil
}

// validateUser validates required fields
func validateUser(user *User) error {
	if user.Email == "" {
		return errors.New("email is required")
	}
	if user.FirstName == "" {
		return errors.New("firstName is required")
	}
	if user.LastName == "" {
		return errors.New("lastName is required")
	}
	if user.Provider == "" {
		return errors.New("provider is required")
	}
	if user.Status == "" {
		return errors.New("status is required")
	}
	if !isValidStatus(user.Status) {
		return fmt.Errorf("invalid status: %s (must be active, inactive, pending, or anonymous)", user.Status)
	}
	return nil
}

// isValidStatus checks if status is valid
func isValidStatus(status string) bool {
	validStatuses := map[string]bool{
		"active":    true,
		"inactive":  true,
		"pending":   true,
		"anonymous": true,
	}
	return validStatuses[status]
}

// HandleCreateUser creates a new user
func (s *Server) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	created, err := s.userStore.CreateUser(&user)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, created)
}

// HandleListUsers lists all users with pagination and search
func (s *Server) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	pageStr := r.URL.Query().Get("page")
	pageSizeStr := r.URL.Query().Get("pageSize")
	search := r.URL.Query().Get("q")

	page := 1
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	pageSize := 10
	if pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	users, totalCount, err := s.userStore.ListUsers(page, pageSize, search)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list users"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"page":       page,
		"pageSize":   pageSize,
		"totalCount": totalCount,
		"data":       users,
	})
}

// HandleGetUser retrieves a specific user by ID
func (s *Server) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	userID := r.PathValue("id")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user id is required"})
		return
	}

	user, err := s.userStore.GetUser(userID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// HandleUpdateUser updates a user
func (s *Server) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	userID := r.PathValue("id")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user id is required"})
		return
	}

	var updates map[string]any
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	user, err := s.userStore.UpdateUser(userID, updates)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// HandleDeleteUser deletes a user (soft-delete)
func (s *Server) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	userID := r.PathValue("id")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user id is required"})
		return
	}

	err = s.userStore.DeleteUser(userID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
