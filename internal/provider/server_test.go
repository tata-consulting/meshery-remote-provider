package provider

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCapabilitiesRoutes(t *testing.T) {
	t.Parallel()

	server := NewServer(LoadConfig())

	for _, path := range []string{"/capabilities", "/v1.0.0/capabilities"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()

		server.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s returned status %d", path, rec.Code)
		}

		var payload map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("failed to decode %s response: %v", path, err)
		}

		if payload["providerName"] != "Tata Consulting" {
			t.Fatalf("unexpected provider name for %s: %#v", path, payload["providerName"])
		}

		capabilities, ok := payload["capabilities"].([]any)
		if !ok {
			t.Fatalf("unexpected capabilities payload for %s: %#v", path, payload["capabilities"])
		}

		if !hasCapability(capabilities, "connections", "/api/connections") {
			t.Fatalf("expected connections capability for %s", path)
		}
		if !hasCapability(capabilities, "credentials", "/api/credentials") {
			t.Fatalf("expected credentials capability for %s", path)
		}
		if !hasCapability(capabilities, "environments", "/api/environments") {
			t.Fatalf("expected environments capability for %s", path)
		}
	}
}

func TestLoginRedirectsBackToMesheryTokenHandler(t *testing.T) {
	t.Parallel()

	server := NewServer(LoadConfig())
	source := base64.RawURLEncoding.EncodeToString([]byte("https://meshery.example.com"))

	req := httptest.NewRequest(http.MethodGet, "/login?source="+url.QueryEscape(source), nil)
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatal("expected redirect location")
	}

	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect url: %v", err)
	}

	if redirectURL.String() == "https://meshery.example.com" {
		t.Fatal("expected redirect to Meshery token callback, got source base url")
	}

	if redirectURL.Path != "/api/user/token" {
		t.Fatalf("unexpected redirect path: %s", redirectURL.Path)
	}

	query := redirectURL.Query()
	if query.Get("token") == "" {
		t.Fatal("expected token query parameter")
	}
	if query.Get("session_cookie") == "" {
		t.Fatal("expected session_cookie query parameter")
	}

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != "session_cookie" {
		t.Fatal("expected session cookie to be set on provider response")
	}
}

func TestProfileRequiresValidBearerToken(t *testing.T) {
	t.Parallel()

	cfg := LoadConfig()
	server := NewServer(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/identity/users/profile", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}

	token, err := server.mintToken()
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/identity/users/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with bearer token, got %d", rec.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode profile response: %v", err)
	}

	if payload["userId"] != cfg.DefaultUser.UserID {
		t.Fatalf("unexpected userId: %#v", payload["userId"])
	}
}

func TestConnectionsCRUD(t *testing.T) {
	t.Parallel()

	server := NewServer(LoadConfig())

	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}

	req = authenticatedRequest(t, server, http.MethodPost, "/api/connections", `{
		"name":"Production Cluster",
		"kind":"kubernetes",
		"type":"platform",
		"sub_type":"orchestrator",
		"status":"connected",
		"credential_id":"4b0bcdb1-55ad-4753-bcf2-c6f8af4eca61",
		"metadata":{"server":"https://cluster.example.com","namespace":"meshery"}
	}`)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 on create, got %d", rec.Code)
	}

	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to decode create response: %v", err)
	}

	connectionID, ok := created["id"].(string)
	if !ok || connectionID == "" {
		t.Fatalf("expected created connection id, got %#v", created["id"])
	}
	if created["sub_type"] != "orchestrator" {
		t.Fatalf("expected sub_type to be preserved, got %#v", created["sub_type"])
	}

	req = authenticatedRequest(t, server, http.MethodGet, "/api/connections?page=1&pageSize=10&search=production", "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on list, got %d", rec.Code)
	}

	var listed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}

	if listed["totalCount"] != float64(1) {
		t.Fatalf("expected one connection in totalCount, got %#v", listed["totalCount"])
	}

	data, ok := listed["data"].([]any)
	if !ok || len(data) != 1 {
		t.Fatalf("expected one connection in data, got %#v", listed["data"])
	}

	req = authenticatedRequest(t, server, http.MethodGet, "/api/connections/"+connectionID, "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on get, got %d", rec.Code)
	}

	req = authenticatedRequest(t, server, http.MethodPut, "/api/connections/"+connectionID, `{
		"name":"Staging Cluster",
		"status":"maintenance",
		"credentialId":"f05d1c4e-121e-490a-a1cc-bda2642f1c1f",
		"metadata":{"server":"https://staging.example.com","namespace":"meshery-system"}
	}`)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on update, got %d", rec.Code)
	}

	var updated map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("failed to decode update response: %v", err)
	}

	if updated["name"] != "Staging Cluster" {
		t.Fatalf("expected updated name, got %#v", updated["name"])
	}
	if updated["status"] != "maintenance" {
		t.Fatalf("expected updated status, got %#v", updated["status"])
	}
	if updated["credential_id"] != "f05d1c4e-121e-490a-a1cc-bda2642f1c1f" {
		t.Fatalf("expected updated credential id, got %#v", updated["credential_id"])
	}

	req = authenticatedRequest(t, server, http.MethodDelete, "/api/connections/"+connectionID, "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on delete, got %d", rec.Code)
	}

	req = authenticatedRequest(t, server, http.MethodGet, "/api/connections/"+connectionID, "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", rec.Code)
	}
}

func TestCredentialsCollectionCRUD(t *testing.T) {
	t.Parallel()

	server := NewServer(LoadConfig())

	req := httptest.NewRequest(http.MethodGet, "/api/credentials", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}

	req = authenticatedRequest(t, server, http.MethodPost, "/api/credentials", `{
		"name":"GitHub Token",
		"kind":"git",
		"type":"token",
		"sub_type":"personal-access-token",
		"metadata":{"provider":"github"},
		"secret":{"token":"ghp_example"}
	}`)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 on create, got %d", rec.Code)
	}

	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to decode create response: %v", err)
	}

	if created["id"] == "" {
		t.Fatalf("expected created credential id, got %#v", created["id"])
	}
	if created["sub_type"] != "personal-access-token" {
		t.Fatalf("expected sub_type to be preserved, got %#v", created["sub_type"])
	}

	req = authenticatedRequest(t, server, http.MethodGet, "/api/credentials", "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on list, got %d", rec.Code)
	}

	var listed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}

	if listed["totalCount"] != float64(1) {
		t.Fatalf("expected one credential in totalCount, got %#v", listed["totalCount"])
	}

	data, ok := listed["data"].([]any)
	if !ok || len(data) != 1 {
		t.Fatalf("expected one credential in data, got %#v", listed["data"])
	}
}

func TestCredentialItemCRUD(t *testing.T) {
	t.Parallel()

	server := NewServer(LoadConfig())

	req := authenticatedRequest(t, server, http.MethodPost, "/api/credentials", `{
		"name":"Cluster Token",
		"kind":"kubernetes",
		"type":"bearer",
		"metadata":{"cluster":"prod"},
		"secret":{"token":"token-1"}
	}`)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 on create, got %d", rec.Code)
	}

	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to decode create response: %v", err)
	}

	credentialID, ok := created["id"].(string)
	if !ok || credentialID == "" {
		t.Fatalf("expected created credential id, got %#v", created["id"])
	}

	req = authenticatedRequest(t, server, http.MethodGet, "/api/credentials/"+credentialID, "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on get, got %d", rec.Code)
	}

	req = authenticatedRequest(t, server, http.MethodPut, "/api/credentials/"+credentialID, `{
		"name":"Cluster Token Rotated",
		"subType":"service-account",
		"secret":{"token":"token-2"}
	}`)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on update, got %d", rec.Code)
	}

	var updated map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("failed to decode update response: %v", err)
	}

	if updated["name"] != "Cluster Token Rotated" {
		t.Fatalf("expected updated name, got %#v", updated["name"])
	}
	if updated["sub_type"] != "service-account" {
		t.Fatalf("expected updated sub_type, got %#v", updated["sub_type"])
	}

	req = authenticatedRequest(t, server, http.MethodDelete, "/api/credentials/"+credentialID, "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on delete, got %d", rec.Code)
	}

	req = authenticatedRequest(t, server, http.MethodGet, "/api/credentials/"+credentialID, "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", rec.Code)
	}
}

func TestCredentialsListSupportsSearchAndPagination(t *testing.T) {
	t.Parallel()

	server := NewServer(LoadConfig())

	for _, payload := range []string{
		`{"name":"GitHub PAT","kind":"git","type":"token","metadata":{"provider":"github"},"secret":{"token":"one"}}`,
		`{"name":"GitLab PAT","kind":"git","type":"token","metadata":{"provider":"gitlab"},"secret":{"token":"two"}}`,
	} {
		req := authenticatedRequest(t, server, http.MethodPost, "/api/credentials", payload)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201 on create, got %d", rec.Code)
		}
	}

	req := authenticatedRequest(t, server, http.MethodGet, "/api/credentials?search=github&page=1&pageSize=1", "")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on filtered list, got %d", rec.Code)
	}

	var listed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("failed to decode filtered list response: %v", err)
	}

	if listed["totalCount"] != float64(1) {
		t.Fatalf("expected one credential in filtered totalCount, got %#v", listed["totalCount"])
	}
	if listed["page_size"] != float64(1) {
		t.Fatalf("expected page_size alias, got %#v", listed["page_size"])
	}

	data, ok := listed["data"].([]any)
	if !ok || len(data) != 1 {
		t.Fatalf("expected one filtered credential, got %#v", listed["data"])
	}
}

func TestEnvironmentsReadSurface(t *testing.T) {
	t.Parallel()

	server := NewServer(LoadConfig())

	req := httptest.NewRequest(http.MethodGet, "/api/environments", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}

	req = authenticatedRequest(t, server, http.MethodGet, "/api/environments", "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on environment list, got %d", rec.Code)
	}

	var listed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("failed to decode environment list response: %v", err)
	}

	if listed["totalCount"] != float64(1) {
		t.Fatalf("expected one seeded environment, got %#v", listed["totalCount"])
	}

	data, ok := listed["data"].([]any)
	if !ok || len(data) != 1 {
		t.Fatalf("expected one environment in data, got %#v", listed["data"])
	}

	item, ok := data[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected environment payload: %#v", data[0])
	}

	environmentID, ok := item["id"].(string)
	if !ok || environmentID == "" {
		t.Fatalf("expected environment id, got %#v", item["id"])
	}

	req = authenticatedRequest(t, server, http.MethodGet, "/api/environments/"+environmentID, "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on environment get, got %d", rec.Code)
	}
}

func TestEnvironmentCreate(t *testing.T) {
	t.Parallel()

	server := NewServer(LoadConfig())

	req := authenticatedRequest(t, server, http.MethodPost, "/api/environments", `{
		"name":"Staging Environment",
		"description":"Pre-production workspace",
		"organization_id":"7df34ef4-d478-44d6-a657-1db6c633f0cb",
		"metadata":{"region":"us-east-1"}
	}`)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 on environment create, got %d", rec.Code)
	}

	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to decode environment create response: %v", err)
	}

	if created["organization_id"] != defaultOrganizationID {
		t.Fatalf("expected organization_id alias, got %#v", created["organization_id"])
	}

	req = authenticatedRequest(t, server, http.MethodGet, "/api/environments", "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on environment list after create, got %d", rec.Code)
	}

	var listed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("failed to decode environment list response: %v", err)
	}

	if listed["totalCount"] != float64(2) {
		t.Fatalf("expected two environments after create, got %#v", listed["totalCount"])
	}
}

func TestEnvironmentUpdate(t *testing.T) {
	t.Parallel()

	server := NewServer(LoadConfig())

	req := authenticatedRequest(t, server, http.MethodGet, "/api/environments", "")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on environment list, got %d", rec.Code)
	}

	var listed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("failed to decode environment list response: %v", err)
	}

	data := listed["data"].([]any)
	item := data[0].(map[string]any)
	environmentID := item["id"].(string)

	req = authenticatedRequest(t, server, http.MethodPut, "/api/environments/"+environmentID, `{
		"name":"Default Environment Updated",
		"description":"Updated description",
		"organizationId":"7df34ef4-d478-44d6-a657-1db6c633f0cb",
		"metadata":{"workspaceId":"f893c289-5587-4c54-a8ff-d291f626d6f5","provider":"remote","region":"us-west-2"}
	}`)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on environment update, got %d", rec.Code)
	}

	var updated map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("failed to decode environment update response: %v", err)
	}

	if updated["name"] != "Default Environment Updated" {
		t.Fatalf("expected updated environment name, got %#v", updated["name"])
	}
}

func TestEnvironmentsListSupportsSearchAndDelete(t *testing.T) {
	t.Parallel()

	server := NewServer(LoadConfig())

	req := authenticatedRequest(t, server, http.MethodPost, "/api/environments", `{
		"name":"Preview Environment",
		"description":"Ephemeral environment",
		"metadata":{"region":"eu-west-1"}
	}`)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 on environment create, got %d", rec.Code)
	}

	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to decode environment create response: %v", err)
	}

	environmentID := created["id"].(string)

	req = authenticatedRequest(t, server, http.MethodGet, "/api/environments?search=preview&page=1&pageSize=1", "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on filtered environment list, got %d", rec.Code)
	}

	var listed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("failed to decode filtered environment list response: %v", err)
	}

	if listed["totalCount"] != float64(1) {
		t.Fatalf("expected one filtered environment, got %#v", listed["totalCount"])
	}
	if listed["page_size"] != float64(1) {
		t.Fatalf("expected page_size alias, got %#v", listed["page_size"])
	}

	req = authenticatedRequest(t, server, http.MethodDelete, "/api/environments/"+environmentID, "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on environment delete, got %d", rec.Code)
	}

	req = authenticatedRequest(t, server, http.MethodGet, "/api/environments/"+environmentID, "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on deleted environment lookup, got %d", rec.Code)
	}
}

func TestCredentialValidation(t *testing.T) {
	t.Parallel()

	server := NewServer(LoadConfig())

	req := authenticatedRequest(t, server, http.MethodPost, "/api/credentials", `{"name":"","kind":"git","type":"token"}`)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid credential create, got %d", rec.Code)
	}

	req = authenticatedRequest(t, server, http.MethodPost, "/api/credentials", `{"name":"Valid","kind":"git","type":"token"}`)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 on valid credential create, got %d", rec.Code)
	}

	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to decode credential create response: %v", err)
	}

	req = authenticatedRequest(t, server, http.MethodPut, "/api/credentials/"+created["id"].(string), `{"type":""}`)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid credential update, got %d", rec.Code)
	}
}

func TestEnvironmentValidation(t *testing.T) {
	t.Parallel()

	server := NewServer(LoadConfig())

	req := authenticatedRequest(t, server, http.MethodPost, "/api/environments", `{"description":"missing name"}`)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid environment create, got %d", rec.Code)
	}

	req = authenticatedRequest(t, server, http.MethodGet, "/api/environments", "")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on environment list, got %d", rec.Code)
	}

	var listed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("failed to decode environment list response: %v", err)
	}

	item := listed["data"].([]any)[0].(map[string]any)
	req = authenticatedRequest(t, server, http.MethodPut, "/api/environments/"+item["id"].(string), `{"name":""}`)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid environment update, got %d", rec.Code)
	}
}

func authenticatedRequest(t *testing.T, server *Server, method, path, body string) *http.Request {
	t.Helper()

	token, err := server.mintToken()
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	return req
}

func hasCapability(capabilities []any, feature, endpoint string) bool {
	for _, item := range capabilities {
		capability, ok := item.(map[string]any)
		if !ok {
			continue
		}

		if capability["feature"] == feature && capability["endpoint"] == endpoint {
			return true
		}
	}

	return false
}
