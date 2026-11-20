package provider

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
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
	cfg          Config
	mux          *http.ServeMux
	connections  *connectionStore
	credentials  *credentialStore
	environments *environmentStore
	workspaces   *workspaceStore
	organizations *organizationStore
	userStore    *UserStore
}

func NewServer(cfg Config) *Server {
	server := &Server{
		cfg:          cfg,
		mux:          http.NewServeMux(),
		connections:  newConnectionStore(),
		credentials:  newCredentialStore(),
		environments: newEnvironmentStore(),
		workspaces:   newWorkspaceStore(),
		organizations: newOrganizationStore(),
		userStore:    NewUserStore(),
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
	s.mux.HandleFunc("GET /api/users", s.HandleListUsers)
	s.mux.HandleFunc("POST /api/users", s.HandleCreateUser)
	s.mux.HandleFunc("GET /api/users/{id}", s.HandleGetUser)
	s.mux.HandleFunc("PUT /api/users/{id}", s.HandleUpdateUser)
	s.mux.HandleFunc("DELETE /api/users/{id}", s.HandleDeleteUser)
	s.mux.HandleFunc("GET /api/identity/orgs", s.handleOrganizations)
	s.mux.HandleFunc("GET /api/organizations", s.handleOrganizations)
	s.mux.HandleFunc("POST /api/organizations", s.handleOrganizations)
	s.mux.HandleFunc("GET /api/organizations/{id}", s.handleOrganizationByID)
	s.mux.HandleFunc("PUT /api/organizations/{id}", s.handleOrganizationByID)
	s.mux.HandleFunc("DELETE /api/organizations/{id}", s.handleOrganizationByID)
	s.mux.HandleFunc("GET /api/credentials", s.handleCredentials)
	s.mux.HandleFunc("POST /api/credentials", s.handleCredentials)
	s.mux.HandleFunc("GET /api/credentials/{id}", s.handleCredentialByID)
	s.mux.HandleFunc("PUT /api/credentials/{id}", s.handleCredentialByID)
	s.mux.HandleFunc("DELETE /api/credentials/{id}", s.handleCredentialByID)
	s.mux.HandleFunc("GET /api/environments", s.handleEnvironments)
	s.mux.HandleFunc("POST /api/environments", s.handleEnvironments)
	s.mux.HandleFunc("GET /api/environments/{id}", s.handleEnvironmentByID)
	s.mux.HandleFunc("PUT /api/environments/{id}", s.handleEnvironmentByID)
	s.mux.HandleFunc("DELETE /api/environments/{id}", s.handleEnvironmentByID)
	s.mux.HandleFunc("GET /api/workspaces", s.handleWorkspaces)
	s.mux.HandleFunc("POST /api/workspaces", s.handleWorkspaces)
	s.mux.HandleFunc("GET /api/workspaces/{id}", s.handleWorkspaceByID)
	s.mux.HandleFunc("PUT /api/workspaces/{id}", s.handleWorkspaceByID)
	s.mux.HandleFunc("DELETE /api/workspaces/{id}", s.handleWorkspaceByID)
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
			"/api/organizations",
			"/api/organizations/{id}",
			"/api/credentials",
			"/api/credentials/{id}",
			"/api/environments",
			"/api/environments/{id}",
			"/api/workspaces",
			"/api/workspaces/{id}",
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
			"Authenticated profile, credential, environment, and workspace stubs",
			"Connection CRUD endpoints for remote provider development",
			"Ready to replace with a production IdP and persistence APIs",
		},
		"providerUrl": providerURL,
		"capabilities": []map[string]string{
			{"feature": "users-profile", "endpoint": "/api/identity/users/profile"},
			{"feature": "users-identity", "endpoint": "/api/users"},
			{"feature": "users", "endpoint": "/api/users"},
			{"feature": "organizations", "endpoint": "/api/organizations"},
			{"feature": "credentials", "endpoint": "/api/credentials"},
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
	rawSource := r.URL.Query().Get("source")

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		if errDesc == "" {
			errDesc = errParam
		}
		s.respondLoginFailure(w, r, http.StatusUnauthorized, errDesc, rawSource)
		return
	}

	callbackBase, err := decodeSource(rawSource)
	if err != nil {
		s.respondLoginFailure(w, r, http.StatusBadRequest, "invalid source query parameter", rawSource)
		return
	}

	token, err := s.mintToken()
	if err != nil {
		s.respondLoginFailure(w, r, http.StatusInternalServerError, "unable to mint token", rawSource)
		return
	}

	sessionID, err := randomString(32)
	if err != nil {
		s.respondLoginFailure(w, r, http.StatusInternalServerError, "unable to create session", rawSource)
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
		s.respondLoginFailure(w, r, http.StatusBadRequest, "invalid decoded source URL", rawSource)
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

func (s *Server) respondLoginFailure(w http.ResponseWriter, r *http.Request, statusCode int, message string, rawSource string) {
	backURL := resolveBackToLoginURL(rawSource)

	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(statusCode)

		_ = loginErrorTemplate.Execute(w, map[string]string{
			"Title":        "Login Failed",
			"Message":      message,
			"BackToLogin":  backURL,
			"ProviderName": s.cfg.ProviderName,
		})
		return
	}

	writeJSON(w, statusCode, map[string]string{
		"error": message,
	})
}

func resolveBackToLoginURL(encodedSource string) string {
	if encodedSource == "" {
		return "/"
	}

	decoded, err := decodeSource(encodedSource)
	if err != nil {
		return "/"
	}

	parsed, err := url.Parse(decoded)
	if err != nil {
		return "/"
	}

	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "/"
	}

	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/user/login"
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return parsed.String()
}

var loginErrorTemplate = template.Must(template.New("login_error").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>{{.Title}} - {{.ProviderName}}</title>
	<style>
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
			background-color: #f8fafc;
			color: #1e293b;
			display: flex;
			align-items: center;
			justify-content: center;
			min-height: 100vh;
			margin: 0;
			padding: 1rem;
		}
		.card {
			background: #ffffff;
			border: 1px solid #e2e8f0;
			border-radius: 8px;
			box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
			max-width: 440px;
			width: 100%;
			padding: 2rem;
			text-align: center;
		}
		h1 {
			font-size: 1.25rem;
			color: #dc2626;
			margin-top: 0;
			margin-bottom: 0.75rem;
		}
		p {
			font-size: 0.95rem;
			color: #64748b;
			margin-bottom: 1.5rem;
			line-height: 1.5;
		}
		.btn {
			display: inline-block;
			background-color: #00b39f;
			color: #ffffff;
			text-decoration: none;
			font-weight: 500;
			font-size: 0.95rem;
			padding: 0.625rem 1.25rem;
			border-radius: 6px;
			transition: background-color 0.15s ease-in-out;
		}
		.btn:hover {
			background-color: #008f7f;
		}
	</style>
</head>
<body>
	<div class="card">
		<h1>{{.Title}}</h1>
		<p>{{.Message}}</p>
		<a class="btn" href="{{.BackToLogin}}">Back to login</a>
	</div>
</body>
</html>
`))

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
				"id":   defaultOrganizationID,
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
			"selectedOrganizationId":    defaultOrganizationID,
			"selectedWorkspaceForOrganizations": map[string]string{
				defaultOrganizationID: defaultWorkspaceID,
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
