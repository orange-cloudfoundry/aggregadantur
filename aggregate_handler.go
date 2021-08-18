package aggregadantur

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/orange-cloudfoundry/aggregadantur/contexes"
	"github.com/orange-cloudfoundry/aggregadantur/models"
)

type AggregateHandler struct {
	next       http.Handler
	aggrRoute  *models.AggregateRoute
	httpClient *http.Client
}

type Result = struct {
	data interface{}
	code int
}

func NewAggregateHandler(next http.Handler, aggrRoute *models.AggregateRoute, httpClient *http.Client) *AggregateHandler {
	return &AggregateHandler{next: next, aggrRoute: aggrRoute, httpClient: httpClient}
}

func (a AggregateHandler) aggregatorMode(req *http.Request) AggregateMode {
	aggregatorModeHeader := req.Header.Get(XAggregatorModeHeader)
	if aggregatorModeHeader != "" {
		return AggregateMode(strings.ToLower(aggregatorModeHeader))
	}
	return AggregateMode(strings.ToLower(req.URL.Query().Get("aggregator_mode")))
}

func (a AggregateHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !a.aggrRoute.IsMethodAllowedMethod(req) {
		a.next.ServeHTTP(w, req)
		return
	}
	if a.aggregatorMode(req) != AggregateModeDefault {
		a.next.ServeHTTP(w, req)
		return
	}
	if !a.aggrRoute.MatchInclude(req) {
		a.next.ServeHTTP(w, req)
		return
	}
	endpoints := a.findEndpointsFromRequest(req)
	syncMap := &sync.Map{}
	wg := &sync.WaitGroup{}
	wg.Add(len(endpoints))
	username := contexes.Username(req)
	scopes := contexes.Scopes(req)

	var previousData []byte
	if req.Body != nil {
		previousData, _ = ioutil.ReadAll(req.Body)
	}

	for _, endpoint := range endpoints {
		var body io.Reader = nil
		if len(previousData) > 0 {
			body = bytes.NewBuffer(previousData)
		}
		reqEndpoint, err := http.NewRequest(req.Method, req.URL.String(), body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		query := reqEndpoint.URL.Query()
		query.Del("aggregator_targets")
		query.Del("aggregator_mode")
		reqEndpoint.URL.RawQuery = query.Encode()
		if authToken := req.Header.Get("Authorization"); authToken != "" {
			reqEndpoint.Header.Set("Authorization", authToken)
		}
		if len(scopes) > 0 {
			reqEndpoint.Header.Set(XAggregatorScopesHeader, strings.Join(scopes, ","))
		}
		if username != "" {
			reqEndpoint.Header.Set(XAggregatorUsernameHeader, username)
		}
		reqEndpoint.Header.Set("Accept", "application/json")
		a.aggrRoute.InjectByEndpoint(reqEndpoint, endpoint)
		isHandler := reqEndpoint.Context().Value(models.IsHandlerContextUpstream)
		if isHandler != nil && isHandler.(bool) {
			go a.aggregateFromHandler(a.aggrRoute.Upstream.Handler, reqEndpoint, endpoint, syncMap, wg)
		} else {
			go a.aggregateFromEndpoint(reqEndpoint, endpoint, syncMap, wg)
		}
	}
	wg.Wait()

	finalCode := 200
	finalMap := make(map[string]interface{})
	syncMap.Range(func(key interface{}, value interface{}) bool {
		result := value.(Result)
		if result.code > finalCode {
			finalCode = result.code
		}
		finalMap[key.(string)] = result.data
		return true
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(finalCode)
	marshaler := json.NewEncoder(w)
	err := marshaler.Encode(finalMap)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// aggregateFromHandler - populates syncMap with handler result
// 1. inject extended error format
// 2. inject json object
// 3. inject fallback raw string
func (a AggregateHandler) aggregateFromHandler(handler http.Handler, reqEndpoint *http.Request, endpoint models.AggregateEndpoint, syncMap *sync.Map, wg *sync.WaitGroup) {
	var (
		value interface{}
	)

	defer wg.Done()
	rawMessage := json.RawMessage{}
	respWriter := httptest.NewRecorder()
	handler.ServeHTTP(respWriter, reqEndpoint)

	if respWriter.Code > 399 {
		// 1.
		value = map[string]interface{}{
			"error_from_endpoint": respWriter.Body.String(),
			"status_code":         respWriter.Code,
		}
	} else if json.Unmarshal(respWriter.Body.Bytes(), &rawMessage) == nil {
		// 2.
		value = rawMessage
	} else {
		// 3.
		value = respWriter.Body.String()
	}

	syncMap.Store(endpoint.Identifier, Result{code: respWriter.Code, data: value})
}

// aggregateFromHandler - populates syncMap with peer response
// 1. error before request, inject proxy error with simple error format
// 2. error on reading stream, inject proxy error with simple error format
// 1. inject extended error format
// 2. inject json object
// 3. inject fallback raw string
func (a AggregateHandler) aggregateFromEndpoint(reqEndpoint *http.Request, endpoint models.AggregateEndpoint, syncMap *sync.Map, wg *sync.WaitGroup) {
	defer wg.Done()

	resp, err := a.httpClient.Do(reqEndpoint)
	if err != nil {
		// 1.
		syncMap.Store(
			endpoint.Identifier,
			Result{code: 502, data: map[string]string{"error": err.Error()}},
		)
		return
	}

	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// 2.
		syncMap.Store(
			endpoint.Identifier,
			Result{code: 502, data: map[string]string{"error": err.Error()}},
		)
		return
	}

	var value interface{}
	rawMessage := json.RawMessage{}

	if resp.StatusCode > 399 {
		// 3.
		value = map[string]interface{}{
			"error_from_endpoint": string(b),
			"status_code":         resp.StatusCode,
		}
	} else if json.Unmarshal(b, &rawMessage) == nil {
		// 4.
		value = rawMessage
	} else {
		// 5.
		value = string(b)
	}

	syncMap.Store(endpoint.Identifier, Result{code: resp.StatusCode, data: value})
}

func (a AggregateHandler) targetsFromRequest(req *http.Request) []string {
	targets := req.Header.Get(XAggregatorTargetsHeader)
	if targets != "" {
		return strings.Split(targets, ",")
	}
	targets = req.URL.Query().Get("aggregator_targets")

	if targets != "" {
		return strings.Split(targets, ",")
	}
	return []string{}
}

func (a AggregateHandler) findEndpointsFromRequest(req *http.Request) models.AggregateEndpoints {
	targets := a.targetsFromRequest(req)
	if len(targets) == 0 {
		return a.aggrRoute.AggregateEndpoints
	}
	endpoints := make(models.AggregateEndpoints, 0)
	for _, site := range targets {
		site = strings.TrimSpace(site)
		for _, endpoint := range a.aggrRoute.AggregateEndpoints {
			if endpoint.Identifier == site {
				endpoints = append(endpoints, endpoint)
			}
		}
	}
	return endpoints

}
