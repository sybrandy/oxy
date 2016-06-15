package authorization

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestInvalidAuth(t *testing.T) {
	_, err := New("invalid", "test_configs/realmonly.json")
	if err == nil {
		t.Error("No error reported for an invalid authorization module.")
	}
}

func TestDefaultAuth(t *testing.T) {
	auth, err := New("default", "")
	if err != nil {
		t.Error("Got an error instantiating the default authorization module.")
	}
	if !auth.Authorize(&httptest.ResponseRecorder{}, nil) {
		t.Error("Expected a 'true' from the default Authorize method.")
	}
	auth, err = New("", "test_configs/realmonly.json")
	if err != nil {
		t.Error("Got an error instantiating the default authorization module.")
	}
	if !auth.Authorize(&httptest.ResponseRecorder{}, nil) {
		t.Error("Expected a 'true' from the default Authorize method.")
	}
}

func TestBasicAuthNoconfig(t *testing.T) {
	_, err := New("basic", "")
	if err == nil {
		t.Error("Expected an error due to there not being a config file specified.")
	}
}

func TestBasicAuthNoHeader(t *testing.T) {
	auth, err := New("basic", "test_configs/realmonly.json")
	if err != nil {
		t.Errorf("Got an error instantiating the basic authorization module: %s", err)
	}
	resp := &httptest.ResponseRecorder{}
	if auth.Authorize(resp, &http.Request{}) {
		t.Error("Expected a 'false' from the basic Authorize method.")
	}
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("Invalid return code provided: %d", resp.Code)
	}
	authHeader := resp.Header().Get("WWW-Authenticate")
	if authHeader == "" {
		t.Errorf("No WWW-Authenticate header provided.")
	}
	re := regexp.MustCompile("^Basic realm=")
	if !re.MatchString(authHeader) {
		t.Errorf("Invalid header value for WWW-=Authenticate: %s", authHeader)
	}
}

func TestBasicAuthWrongHeader(t *testing.T) {
	auth, err := New("basic", "test_configs/realmonly.json")
	if err != nil {
		t.Errorf("Got an error instantiating the basic authorization module: %s", err)
	}
	resp := &httptest.ResponseRecorder{}
	req := &http.Request{
		Header: map[string][]string{
			"Authorization": []string{"Invalid blah..."},
		},
	}
	if auth.Authorize(resp, req) {
		t.Error("Expected a 'false' from the basic Authorize method.")
	}
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("Invalid return code provided: %d", resp.Code)
	}
	authHeader := resp.Header().Get("WWW-Authenticate")
	if authHeader == "" {
		t.Errorf("No WWW-Authenticate header provided.")
	}
	re := regexp.MustCompile("^Basic realm=")
	if !re.MatchString(authHeader) {
		t.Errorf("Invalid header value for WWW-=Authenticate: %s", authHeader)
	}
}

func TestBasicAuthInvalidPayload(t *testing.T) {
	auth, err := New("basic", "test_configs/realmonly.json")
	if err != nil {
		t.Errorf("Got an error instantiating the basic authorization module: %s", err)
	}
	resp := &httptest.ResponseRecorder{}
	req := &http.Request{
		Header: map[string][]string{
			"Authorization": []string{"Basic blah..."},
		},
	}
	if auth.Authorize(resp, req) {
		t.Error("Expected a 'false' from the basic Authorize method.")
	}
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("Invalid return code provided: %d", resp.Code)
	}
	authHeader := resp.Header().Get("WWW-Authenticate")
	if authHeader == "" {
		t.Errorf("No WWW-Authenticate header provided.")
	}
	re := regexp.MustCompile("^Basic realm=")
	if !re.MatchString(authHeader) {
		t.Errorf("Invalid header value for WWW-=Authenticate: %s", authHeader)
	}
}

func TestBasicAuthInvalidPayloadOnePart(t *testing.T) {
	auth, err := New("basic", "test_configs/realmonly.json")
	if err != nil {
		t.Errorf("Got an error instantiating the basic authorization module: %s", err)
	}
	resp := &httptest.ResponseRecorder{}
	req := &http.Request{
		Header: map[string][]string{
			"Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("user"))},
		},
	}
	if auth.Authorize(resp, req) {
		t.Error("Expected a 'false' from the basic Authorize method.")
	}
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("Invalid return code provided: %d", resp.Code)
	}
	authHeader := resp.Header().Get("WWW-Authenticate")
	if authHeader == "" {
		t.Errorf("No WWW-Authenticate header provided.")
	}
	re := regexp.MustCompile("^Basic realm=")
	if !re.MatchString(authHeader) {
		t.Errorf("Invalid header value for WWW-=Authenticate: %s", authHeader)
	}
}

func TestBasicAuthInvalidPayloadNoPassword(t *testing.T) {
	auth, err := New("basic", "test_configs/realmonly.json")
	if err != nil {
		t.Errorf("Got an error instantiating the basic authorization module: %s", err)
	}
	resp := &httptest.ResponseRecorder{}
	req := &http.Request{
		Header: map[string][]string{
			"Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("user:"))},
		},
	}
	if auth.Authorize(resp, req) {
		t.Error("Expected a 'false' from the basic Authorize method.")
	}
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("Invalid return code provided: %d", resp.Code)
	}
	authHeader := resp.Header().Get("WWW-Authenticate")
	if authHeader == "" {
		t.Errorf("No WWW-Authenticate header provided.")
	}
	re := regexp.MustCompile("^Basic realm=")
	if !re.MatchString(authHeader) {
		t.Errorf("Invalid header value for WWW-=Authenticate: %s", authHeader)
	}
}

func TestBasicAuthInvalidPayloadNoUser(t *testing.T) {
	auth, err := New("basic", "test_configs/realmonly.json")
	if err != nil {
		t.Errorf("Got an error instantiating the basic authorization module: %s", err)
	}
	resp := &httptest.ResponseRecorder{}
	req := &http.Request{
		Header: map[string][]string{
			"Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte(":password"))},
		},
	}
	if auth.Authorize(resp, req) {
		t.Error("Expected a 'false' from the basic Authorize method.")
	}
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("Invalid return code provided: %d", resp.Code)
	}
	authHeader := resp.Header().Get("WWW-Authenticate")
	if authHeader == "" {
		t.Errorf("No WWW-Authenticate header provided.")
	}
	re := regexp.MustCompile("^Basic realm=")
	if !re.MatchString(authHeader) {
		t.Errorf("Invalid header value for WWW-=Authenticate: %s", authHeader)
	}
}

func TestBasicAuthValidUser(t *testing.T) {
	auth, err := New("basic", "test_configs/valid.json")
	if err != nil {
		t.Errorf("Got an error instantiating the basic authorization module: %s", err)
	}
	resp := &httptest.ResponseRecorder{}
	req := &http.Request{
		Header: map[string][]string{
			"Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("foo:bar"))},
		},
	}
	if !auth.Authorize(resp, req) {
		t.Error("Expected a 'true' from the basic Authorize method.")
	}
}

func TestBasicAuthInvalidUser(t *testing.T) {
	auth, err := New("basic", "test_configs/valid.json")
	if err != nil {
		t.Errorf("Got an error instantiating the basic authorization module: %s", err)
	}
	resp := &httptest.ResponseRecorder{}
	req := &http.Request{
		Header: map[string][]string{
			"Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("baz:bar"))},
		},
	}
	if auth.Authorize(resp, req) {
		t.Error("Expected a 'false' from the basic Authorize method.")
	}
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("Invalid return code provided: %d", resp.Code)
	}
	authHeader := resp.Header().Get("WWW-Authenticate")
	if authHeader == "" {
		t.Errorf("No WWW-Authenticate header provided.")
	}
	re := regexp.MustCompile("^Basic realm=")
	if !re.MatchString(authHeader) {
		t.Errorf("Invalid header value for WWW-=Authenticate: %s", authHeader)
	}
}

func TestBasicAuthInvalidPassword(t *testing.T) {
	auth, err := New("basic", "test_configs/valid.json")
	if err != nil {
		t.Errorf("Got an error instantiating the basic authorization module: %s", err)
	}
	resp := &httptest.ResponseRecorder{}
	req := &http.Request{
		Header: map[string][]string{
			"Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("foo:baz"))},
		},
	}
	if auth.Authorize(resp, req) {
		t.Error("Expected a 'false' from the basic Authorize method.")
	}
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("Invalid return code provided: %d", resp.Code)
	}
	authHeader := resp.Header().Get("WWW-Authenticate")
	if authHeader == "" {
		t.Errorf("No WWW-Authenticate header provided.")
	}
	re := regexp.MustCompile("^Basic realm=")
	if !re.MatchString(authHeader) {
		t.Errorf("Invalid header value for WWW-=Authenticate: %s", authHeader)
	}
}
