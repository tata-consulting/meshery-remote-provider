package provider

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type claims struct {
	Sub       string `json:"sub"`
	UserID    string `json:"userId"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type Server struct {
	cfg         Config
	mux         *http.ServeMux
	connections *connectionStore
}

func NewServer(cfg Config) *Server {
	server := &Server{
		cfg:         cfg,
		mux:         http.NewServeMux(),
		connections: newConnectionStore(),
	}

	server.routes()

	return server
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /", s.handleIndex)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /capabilities", s.handleCapabilities)
	s.mux.HandleFunc("GET /{version}/capabilities", s.handleCapabilities)
	s.mux.HandleFunc("GET /login", s.handleLogin)
	s.mux.HandleFunc("GET /logout", s.handleLogout)
	s.mux.HandleFunc("GET /api/identity/users/profile", s.handleProfile)
	s.mux.HandleFunc("GET /api/users", s.handleUsers)
	s.mux.HandleFunc("GET /api/identity/orgs", s.handleOrganizations)
	s.mux.HandleFunc("GET /api/environments", s.handleEnvironments)
	s.mux.HandleFunc("GET /api/workspaces", s.handleWorkspaces)
	s.mux.HandleFunc("GET /api/connections", s.handleConnections)
	s.mux.HandleFunc("POST /api/connections", s.handleConnections)
	s.mux.HandleFunc("GET /api/connections/{id}", s.handleConnectionByID)
	s.mux.HandleFunc("PUT /api/connections/{id}", s.handleConnectionByID)
	s.mux.HandleFunc("DELETE /api/connections/{id}", s.handleConnectionByID)
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":        s.cfg.ProviderName,
		"providerUrl": s.cfg.PublicBaseURL,
		"routes": []string{
			"/capabilities",
			"/{version}/capabilities",
			"/login",
			"/logout",
			"/api/identity/users/profile",
			"/api/users",
			"/api/identity/orgs",
			"/api/environments",
			"/api/workspaces",
			"/api/connections",
			"/api/connections/{id}",
		},
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	providerURL := s.publicBaseURL(r)

	writeJSON(w, http.StatusOK, map[string]any{
		"providerType":   "remote",
		"packageVersion": s.cfg.PackageVersion,
		"providerName":   s.cfg.ProviderName,
		"providerDescription": []string{
			"Starter implementation of a Meshery Remote Provider",
			"Development login flow that redirects back to Meshery",
			"Authenticated profile, org, environment, and workspace stubs",
			"Connection CRUD endpoints for remote provider development",
			"Ready to replace with a production IdP and persistence APIs",
		},
		"providerUrl": providerURL,
		"capabilities": []map[string]string{
			{"feature": "users-profile", "endpoint": "/api/identity/users/profile"},
			{"feature": "users-identity", "endpoint": "/api/users"},
			{"feature": "organizations", "endpoint": "/api/identity/orgs"},
			{"feature": "environments", "endpoint": "/api/environments"},
			{"feature": "workspaces", "endpoint": "/api/workspaces"},
			{"feature": "connections", "endpoint": "/api/connections"},
		},
		"restrictedAccess": map[string]any{
			"isMesheryUIRestricted": false,
			"allowedComponents": map[string]any{
				"navigator": map[string]any{
					"lifecycle":     map[string]any{},
					"configuration": map[string]any{},
				},
				"header": map[string]any{},
			},
		},
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	callbackBase, err := decodeSource(r.URL.Query().Get("source"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid source query parameter"})
		return
	}

	token, err := s.mintToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to mint token"})
		return
	}

	sessionID, err := randomString(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to create session"})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.SessionParam,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	callbackURL, err := buildMesheryCallbackURL(callbackBase)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid decoded source URL"})
		return
	}

	query := callbackURL.Query()
	query.Set(s.cfg.TokenQueryParam, token)
	query.Set(s.cfg.SessionParam, sessionID)
	callbackURL.RawQuery = query.Encode()

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	http.Redirect(w, r, callbackURL.String(), http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.SessionParam,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	currentUser, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	writeJSON(w, http.StatusOK, s.userPayload(currentUser))
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	currentUser, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"page":       1,
		"pageSize":   1,
		"totalCount": 1,
		"data":       []any{s.userPayload(currentUser)},
	})
}

func (s *Server) handleOrganizations(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"page":       1,
		"pageSize":   1,
		"totalCount": 1,
		"data": []map[string]any{{
			"id":          "7df34ef4-d478-44d6-a657-1db6c633f0cb",
			"name":        "Tata Consulting",
			"description": "Starter organization payload for Meshery Remote Provider development.",
			"slug":        "tata-consulting",
		}},
	})
}

func (s *Server) handleEnvironments(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"page":       1,
		"pageSize":   0,
		"totalCount": 0,
		"data":       []any{},
	})
}

func (s *Server) handleWorkspaces(w http.ResponseWriter, r *http.Request) {
	_, err := s.currentUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"page":       1,
		"pageSize":   1,
		"totalCount": 1,
		"data": []map[string]any{{
			"id":             "f893c289-5587-4c54-a8ff-d291f626d6f5",
			"name":           "Default Workspace",
			"description":    "Starter workspace payload for Meshery Remote Provider development.",
			"organizationId": "7df34ef4-d478-44d6-a657-1db6c633f0cb",
		}},
	})
}

func (s *Server) currentUser(r *http.Request) (claims, error) {
	token := bearerToken(r)
	if token == "" {
		return claims{}, errors.New("missing bearer token")
	}

	return s.parseToken(token)
}

func (s *Server) mintToken() (string, error) {
	now := time.Now().UTC()
	return signToken(s.cfg.JWTSecret, claims{
		Sub:       s.cfg.DefaultUser.ID,
		UserID:    s.cfg.DefaultUser.UserID,
		Email:     s.cfg.DefaultUser.Email,
		FirstName: s.cfg.DefaultUser.FirstName,
		LastName:  s.cfg.DefaultUser.LastName,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(),
	})
}

func (s *Server) parseToken(token string) (claims, error) {
	return verifyToken(s.cfg.JWTSecret, token)
}

func (s *Server) userPayload(currentUser claims) map[string]any {
	now := time.Now().UTC().Format(time.RFC3339)

	return map[string]any{
		"id":             currentUser.Sub,
		"userId":         currentUser.UserID,
		"email":          currentUser.Email,
		"firstName":      currentUser.FirstName,
		"lastName":       currentUser.LastName,
		"provider":       strings.ToLower(strings.ReplaceAll(s.cfg.ProviderName, " ", "-")),
		"status":         "active",
		"createdAt":      now,
		"updatedAt":      now,
		"firstLoginTime": now,
		"lastLoginTime":  now,
		"country":        map[string]any{},
		"region":         map[string]any{},
		"organizations": map[string]any{
			"organizationsWithRoles": []map[string]any{{
				"id":   "7df34ef4-d478-44d6-a657-1db6c633f0cb",
				"name": "Tata Consulting",
				"role": "organization admin",
			}},
			"totalCount": 1,
		},
		"teams": map[string]any{
			"teamsWithRoles": []map[string]any{},
			"totalCount":     0,
		},
		"preferences": map[string]any{
			"anonymousPerfResults":      true,
			"anonymousUsageStats":       true,
			"dashboardPreferences":      map[string]any{},
			"remoteProviderPreferences": map[string]any{},
			"selectedOrganizationId":    "7df34ef4-d478-44d6-a657-1db6c633f0cb",
			"selectedWorkspaceForOrganizations": map[string]string{
				"7df34ef4-d478-44d6-a657-1db6c633f0cb": "f893c289-5587-4c54-a8ff-d291f626d6f5",
			},
			"updatedAt":                 now,
			"usersExtensionPreferences": map[string]any{},
		},
	}
}

func (s *Server) publicBaseURL(r *http.Request) string {
	if s.cfg.PublicBaseURL != "" {
		return strings.TrimRight(s.cfg.PublicBaseURL, "/")
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}

	return fmt.Sprintf("%s://%s", scheme, r.Host)
}

func buildMesheryCallbackURL(source string) (*url.URL, error) {
	callbackURL, err := url.Parse(source)
	if err != nil {
		return nil, err
	}
	if callbackURL.Scheme == "" || callbackURL.Host == "" {
		return nil, errors.New("source must be an absolute URL")
	}

	callbackURL.Path = strings.TrimRight(callbackURL.Path, "/") + "/api/user/token"
	callbackURL.RawQuery = ""
	callbackURL.Fragment = ""

	return callbackURL, nil
}

func decodeSource(encoded string) (string, error) {
	if encoded == "" {
		return "", errors.New("missing source")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err == nil {
		return string(decoded), nil
	}

	decoded, err = base64.URLEncoding.DecodeString(encoded)
	if err == nil {
		return string(decoded), nil
	}

	return "", err
}

func bearerToken(r *http.Request) string {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return strings.TrimSpace(authHeader[7:])
	}

	return strings.TrimSpace(r.URL.Query().Get("token"))
}

func randomString(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func signToken(secret string, tokenClaims claims) (string, error) {
	headerJSON, err := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		return "", err
	}

	payloadJSON, err := json.Marshal(tokenClaims)
	if err != nil {
		return "", err
	}

	headerPart := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadPart := base64.RawURLEncoding.EncodeToString(payloadJSON)
	unsignedToken := headerPart + "." + payloadPart

	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(unsignedToken)); err != nil {
		return "", err
	}

	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return unsignedToken + "." + signature, nil
}

func verifyToken(secret, token string) (claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims{}, errors.New("invalid token format")
	}

	unsignedToken := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(unsignedToken)); err != nil {
		return claims{}, err
	}

	expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expectedSignature), []byte(parts[2])) {
		return claims{}, errors.New("invalid token signature")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, err
	}

	var tokenClaims claims
	if err := json.Unmarshal(payloadJSON, &tokenClaims); err != nil {
		return claims{}, err
	}

	if tokenClaims.ExpiresAt > 0 && time.Now().UTC().Unix() > tokenClaims.ExpiresAt {
		return claims{}, errors.New("token expired")
	}

	return tokenClaims, nil
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}
