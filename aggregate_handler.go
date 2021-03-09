package aggregadantur

import (
	"bytes"
	"encoding/json"
	"github.com/orange-cloudfoundry/aggregadantur/contexes"
	"github.com/orange-cloudfoundry/aggregadantur/models"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

type AggregateHandler struct {
	next       http.Handler
	aggrRoute  *models.AggregateRoute
	httpClient *http.Client
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
		if previousData != nil && len(previousData) > 0 {
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
	finalMap := make(map[string]interface{})
	syncMap.Range(func(key, value interface{}) bool {
		finalMap[key.(string)] = value
		return true
	})
	w.Header().Set("Content-Type", "application/json")
	marshaler := json.NewEncoder(w)
	err := marshaler.Encode(finalMap)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (a AggregateHandler) aggregateFromHandler(handler http.Handler, reqEndpoint *http.Request, endpoint models.AggregateEndpoint, syncMap *sync.Map, wg *sync.WaitGroup) {
	defer wg.Done()
	respWriter := httptest.NewRecorder()
	handler.ServeHTTP(respWriter, reqEndpoint)
	if respWriter.Code > 399 {
		syncMap.Store(endpoint.Identifier, map[string]interface{}{
			"error_from_endpoint": respWriter.Body.String(),
			"status_code":         respWriter.Code,
		})
		return
	}

	rawMessage := json.RawMessage{}
	err := json.Unmarshal(respWriter.Body.Bytes(), &rawMessage)
	if err != nil {
		syncMap.Store(endpoint.Identifier, respWriter.Body.String())
		return
	}
	syncMap.Store(endpoint.Identifier, rawMessage)
}

func (a AggregateHandler) aggregateFromEndpoint(reqEndpoint *http.Request, endpoint models.AggregateEndpoint, syncMap *sync.Map, wg *sync.WaitGroup) {
	defer wg.Done()
	resp, err := a.httpClient.Do(reqEndpoint)
	if err != nil {
		syncMap.Store(endpoint.Identifier, map[string]string{
			"error": err.Error(),
		})
		return
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		syncMap.Store(endpoint.Identifier, map[string]string{
			"error": err.Error(),
		})
		return
	}

	if resp.StatusCode > 399 {
		syncMap.Store(endpoint.Identifier, map[string]interface{}{
			"error_from_endpoint": string(b),
			"status_code":         resp.StatusCode,
		})
		return
	}
	rawMessage := json.RawMessage{}
	err = json.Unmarshal(b, &rawMessage)
	if err != nil {
		syncMap.Store(endpoint.Identifier, string(b))
		return
	}
	syncMap.Store(endpoint.Identifier, rawMessage)
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
