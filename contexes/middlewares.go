package contexes

import (
	"github.com/orange-cloudfoundry/aggregadantur/jwtclaim"
	"net/http"
)

const (
	ScopeContextKey MiddlewareContextKey = iota
	UsernameContextKey
	JwtClaimContextKey
)

type MiddlewareContextKey int

// Set the username to a request context
func SetUsername(req *http.Request, username string) {
	AddContextValue(req, UsernameContextKey, username)
}

// Retrieve username from a request context
func Username(req *http.Request) string {
	return GetContextValue(req, UsernameContextKey, "").(string)
}

// set scope to a request context
func SetScopes(req *http.Request, scopes []string) {
	AddContextValue(req, ScopeContextKey, scopes)
}

// retrieve scope from request context
func Scopes(req *http.Request) []string {
	return GetContextValue(req, ScopeContextKey, []string{}).([]string)
}

// set jwt claim to a request context
func SetJwtClaim(req *http.Request, jwtClaim *jwtclaim.ScopeClaims) {
	AddContextValue(req, JwtClaimContextKey, jwtClaim)
}

// retrieve jwt claim from request context
func JwtClaim(req *http.Request) *jwtclaim.ScopeClaims {
	val := GetContextValue(req, ScopeContextKey, nil)
	if val == nil {
		return nil
	}
	return val.(*jwtclaim.ScopeClaims)
}
