package authorization

import (
	"net/http/httptest"
	"testing"
)

func TestInvalidAuth(t *testing.T) {
	_, err := New("invalid", []byte{})
	if err == nil {
		t.Error("No error reported for an invalid authorization module.")
	}
}

func TestDefaultAuth(t *testing.T) {
	auth, err := New("default", []byte{})
	if err != nil {
		t.Error("Got an error instantiating the default authorization module.")
	}
	if !auth.Authorize(&httptest.ResponseRecorder{}, nil) {
		t.Error("Expected a 'true' from the default Authorize method.")
	}
}
