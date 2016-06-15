// package authorization provides an interface for the forwarders
package authorization

import (
	"errors"
	"io/ioutil"
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

func New(authtype string, config string) (Auth, error) {
	if authtype == "" {
		authtype = "default"
	}
	auth, ok := auths[authtype]
	if !ok {
		return nilAuth{}, errors.New(authtype + " is not a valid authorization module.")
	}

	var data []byte
	var err error
	if authtype != "default" {
		if config == "" {
			return nilAuth{}, errors.New("No config file was specified for " + authtype + " authentication.")
		}
		data, err = ioutil.ReadFile(config)
		if err != nil {
			return nilAuth{}, err
		}
	}
	currAuth, err := auth(data)
	return currAuth, err
}
