// Default authorization == No authorization
package authorization

import (
	"net/http"
)

type DefaultAuth struct{}

var _ Auth = DefaultAuth{}

func NewDefaultAuth(config []byte) (Auth, error) {
	return DefaultAuth{}, nil
}

func (a DefaultAuth) Authorize(w http.ResponseWriter, req *http.Request) bool {
	return true
}
