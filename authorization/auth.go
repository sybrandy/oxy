// package authorization provides an interface for the forwarders
package authorization

import (
	"errors"
	"net/http"
)

type Auth interface {
	Authorize(w http.ResponseWriter, req *http.Request) bool
}

// Invalid auth type that always returns false.
type nilAuth struct{}

func (a nilAuth) Authorize(w http.ResponseWriter, req *http.Request) bool {
	return false
}

var auths = map[string]func(config []byte) (Auth, error){
	"default": NewDefaultAuth,
	"basic":   NewBasicAuth,
}

func New(authtype string, config []byte) (Auth, error) {
	auth, ok := auths[authtype]
	if !ok {
		return nilAuth{}, errors.New(authtype + " is not a valid authorization module.")
	}
	currAuth, err := auth(config)
	return currAuth, err
}
