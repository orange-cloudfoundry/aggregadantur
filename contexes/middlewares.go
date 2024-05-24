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

// SetUsername Set the username to a request context
func SetUsername(req *http.Request, username string) {
	AddContextValue(req, UsernameContextKey, username)
}

// Username Retrieve username from a request context
func Username(req *http.Request) string {
	return GetContextValue(req, UsernameContextKey, "").(string)
}

// SetScopes set scope to a request context
func SetScopes(req *http.Request, scopes []string) {
	AddContextValue(req, ScopeContextKey, scopes)
}

// Scopes Retrieve scope from request context
func Scopes(req *http.Request) []string {
	return GetContextValue(req, ScopeContextKey, []string{}).([]string)
}

// SetJwtClaim set jwt claim to a request context
func SetJwtClaim(req *http.Request, jwtClaim *jwtclaim.ScopeClaims) {
	AddContextValue(req, JwtClaimContextKey, jwtClaim)
}

// JwtClaim Retrieve JWT claim from request context
func JwtClaim(req *http.Request) *jwtclaim.ScopeClaims {
	val := GetContextValue(req, JwtClaimContextKey, nil)
	if val == nil {
		return nil
	}
	return val.(*jwtclaim.ScopeClaims)
}
