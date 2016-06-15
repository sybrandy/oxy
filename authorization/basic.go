// Basic Authorization
package authorization

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

type BasicAuth struct {
	Realm string
	Users map[string]interface{}
}

var _ Auth = BasicAuth{}

func NewBasicAuth(config []byte) (Auth, error) {
	auth := BasicAuth{}
	err := json.Unmarshal(config, &auth)
	return auth, err
}

func (a BasicAuth) Authorize(w http.ResponseWriter, req *http.Request) bool {
	auth, ok := req.Header["Authorization"]
	if !ok {
		return returnUnauthorized(w, a.Realm)
	}

	parts := strings.SplitN(auth[0], " ", 2)
	if parts[0] != "Basic" {
		return returnUnauthorized(w, a.Realm)
	}

	payload, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		log.Printf("Error decoding the config: %s\n", err)
		return returnUnauthorized(w, a.Realm)
	}

	credentials := strings.SplitN(string(payload), ":", 2)
	if len(credentials) != 2 || credentials[0] == "" || credentials[1] == "" {
		log.Printf("Invalid credentials provided by the client: %+v\n", credentials)
		return returnUnauthorized(w, a.Realm)
	}

	pass, ok := a.Users[credentials[0]]
	if !ok {
		return returnUnauthorized(w, a.Realm)
	}
	if pass.(string) != credentials[1] {
		return returnUnauthorized(w, a.Realm)
	}
	return true
}

func returnUnauthorized(w http.ResponseWriter, realm string) bool {
	w.Header().Set("WWW-Authenticate", "Basic realm="+realm)
	http.Error(w, "", http.StatusUnauthorized)
	return false
}
