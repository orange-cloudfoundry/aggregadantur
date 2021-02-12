package contexes

import (
	"context"
	"net/http"
)

// Add a context value to an http request without having to override request by yourself
func AddContextValue(req *http.Request, key, val interface{}) {
	parentContext := req.Context()
	ctxValueReq := req.WithContext(context.WithValue(parentContext, key, val))
	*req = *ctxValueReq
}

func GetContextValue(req *http.Request, key interface{}, defaultValue interface{}) interface{} {
	val := req.Context().Value(key)
	if val == nil {
		return defaultValue
	}
	return val
}
