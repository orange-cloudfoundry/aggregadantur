package models

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	IsHandlerContextUpstream CtxUpstream = iota
)

type CtxUpstream int

func NewUpstreamFromUrl(urlRaw string) *Upstream {
	u, err := url.Parse(urlRaw)
	if err != nil {
		panic(err)
	}
	return &Upstream{
		URL: u,
	}
}

func NewUpstreamFromHandler(handler http.Handler) *Upstream {
	return &Upstream{
		Handler: handler,
	}
}

type Upstream struct {
	URL     *url.URL
	Handler http.Handler
}

func (r *Upstream) Load(urlRaw string) error {
	u, err := url.Parse(urlRaw)
	if err != nil {
		return err
	}
	r.URL = u
	return nil
}

func (r *Upstream) UnmarshalCloud(data interface{}) error {
	return r.Load(data.(string))
}

func (r *Upstream) UnmarshalYAML(unmarshal func(interface{}) error) error {
	urlRaw := ""
	var err error
	if err = unmarshal(&urlRaw); err != nil {
		return fmt.Errorf("when unmarshal upstream: %s", err.Error())
	}
	err = r.Load(urlRaw)
	if err != nil {
		return fmt.Errorf("when unmarshal upstream: %s", err.Error())
	}
	return nil
}

func (r *Upstream) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return fmt.Errorf("when unmarshal upstream: %s", err.Error())
	}
	err = r.Load(s)
	if err != nil {
		return fmt.Errorf("when unmarshal upstream: %s", err.Error())
	}
	return nil
}

type AggregateEndpoints []AggregateEndpoint
type AggregateEndpoint struct {
	Url        string `json:"url" yaml:"url" cloud:"url"`
	Identifier string `json:"identifier" yaml:"identifier" cloud:"identifier"`
}

func NewAggregateRoute(
	name string,
	identifier string,
	upstream *Upstream,
	aggrEndpoints AggregateEndpoints,
	auth Auth,
	includes, excludes PathMatchers,
) (*AggregateRoute, error) {
	r := &AggregateRoute{
		Name:               name,
		Includes:           includes,
		Excludes:           excludes,
		Upstream:           upstream,
		NoBuffer:           false,
		InsecureSkipVerify: false,
		OptionsPassthrough: true,
		Hosts:              HostMatchers{NewHostMatcher("*")},
		Auth:               auth,
		Path:               "",
		AggregateEndpoints: aggrEndpoints,
		Identifier:         identifier,
	}
	err := r.Check()
	if err != nil {
		return nil, err
	}
	return r, nil
}

func NewAggregateRouteWithHandler(
	name string,
	identifier string,
	handler http.Handler,
	aggrEndpoints AggregateEndpoints,
	auth Auth,
	includes, excludes PathMatchers,
) (*AggregateRoute, error) {
	return NewAggregateRoute(name, identifier, NewUpstreamFromHandler(handler), aggrEndpoints, auth, includes, excludes)
}

type AggregateRoute struct {
	// Name of your aggregate
	Name string `json:"name" yaml:"name" cloud:"name"`
	// Includes path for making aggregation
	// You can use globs:
	//   - appending /* will only make requests available in first level to aggregate
	//   - appending /** will mark everything to aggregate
	// e.g.: /app/**
	Includes PathMatchers `json:"includes" yaml:"includes" cloud:"includes"`
	// Same pattern has includes but for excludes this time
	Excludes PathMatchers `json:"excludes" yaml:"excludes" cloud:"excludes"`
	// Upstream URL where all request will be redirected
	// Query parameters can be passed, e.g.: http://localhost?param=1
	// User and password are given as basic auth too (this is not recommended to use it), e.g.: http://user:password@localhost
	Upstream *Upstream `json:"upstream" yaml:"upstream" cloud:"upstream"`
	// By default response from upstream are buffered, it can be issue when sending big files
	// Set to true to stream response
	NoBuffer bool `json:"no_buffer" yaml:"no_buffer" cloud:"no_buffer"`
	// Set to true to not check ssl certificates from upstream (not really recommended)
	InsecureSkipVerify bool `json:"insecure_skip_verify" yaml:"insecure_skip_verify" cloud:"insecure_skip_verify"`
	// Will forward directly to proxified route OPTIONS method without using middlewares
	OptionsPassthrough bool `json:"options_passthrough" yaml:"options_passthrough" cloud:"options_passthrough"`
	// Must match host
	Hosts HostMatchers `json:"hosts" yaml:"hosts" cloud:"hosts"`
	// Auth
	Auth Auth `json:"auth" yaml:"auth" cloud:"auth"`
	// Path
	Path string `json:"path" yaml:"path" cloud:"path"`
	// endpoints
	AggregateEndpoints AggregateEndpoints `json:"aggregate_endpoints" yaml:"aggregate_endpoints" cloud:"aggregate_endpoints"`
	Identifier         string             `json:"identifier" yaml:"identifier" cloud:"identifier"`
}

func (r *AggregateRoute) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain AggregateRoute
	var err error
	if err = unmarshal((*plain)(r)); err != nil {
		return fmt.Errorf("when unmarshal aggregate_route: %s", err.Error())
	}
	err = r.Load()
	if err != nil {
		return fmt.Errorf("when unmarshal aggregate_route: %s", err.Error())
	}
	return nil
}

func (r *AggregateRoute) Load() error {
	if r.Hosts == nil || len(r.Hosts) == 0 {
		r.Hosts = HostMatchers{NewHostMatcher("*")}
	}

	return r.Check()
}

func (r *AggregateRoute) Check() error {
	if r.Name == "" {
		return fmt.Errorf("You must provide a name to your routes")
	}
	if r.Identifier == "" {
		return fmt.Errorf("You must provide an identifier to your routes")
	}

	if r.Upstream != nil && r.Upstream.URL != nil && r.Upstream.URL.Scheme == "" {
		return fmt.Errorf("Invalid URL : scheme is missing")
	}
	if r.Path == "" {
		r.Path = "/"
	}
	return nil
}

func (r *AggregateRoute) InjectForwardUrl(req *http.Request) {
	if r.Upstream.Handler != nil {
		parentContext := req.Context()
		ctxValueReq := req.WithContext(context.WithValue(parentContext, IsHandlerContextUpstream, true))
		*req = *ctxValueReq
		return
	}
	if r.Path != "/" {
		req.URL.Path = strings.TrimPrefix(req.URL.Path, r.Path)
	}
	if r.Upstream.URL.User != nil {
		user := r.Upstream.URL.User.Username()
		password, _ := r.Upstream.URL.User.Password()
		req.SetBasicAuth(user, password)
	}
	if r.Upstream.URL.RawQuery != "" {
		queryUpstream := r.Upstream.URL.Query()
		query := req.URL.Query()
		for k, v := range queryUpstream {
			query[k] = v
		}
		req.URL.RawQuery = query.Encode()
	}
	req.URL.Scheme = r.Upstream.URL.Scheme
	req.URL.Host = r.Upstream.URL.Host
	req.RequestURI = req.URL.RequestURI()
}

func (r *AggregateRoute) InjectByEndpoint(req *http.Request, endpoint AggregateEndpoint) {
	if endpoint.Identifier == r.Identifier {
		r.InjectForwardUrl(req)
		req.RequestURI = ""
		return
	}
	if r.Path != "/" {
		req.URL.Path = strings.TrimPrefix(req.URL.Path, r.Path)
	}
	u, _ := url.Parse(endpoint.Url)

	if u.Path != "" && u.Path != "/" {
		req.URL.Path = u.Path + req.URL.Path
	}
	if u.User != nil {
		user := u.User.Username()
		password, _ := u.User.Password()
		req.SetBasicAuth(user, password)
	}
	if u.RawQuery != "" {
		queryUpstream := u.Query()
		query := req.URL.Query()
		for k, v := range queryUpstream {
			query[k] = v
		}
		req.URL.RawQuery = query.Encode()
	}
	if u.Scheme != "" {
		req.URL.Scheme = u.Scheme
	}
	req.URL.Host = u.Host

}

func (r *AggregateRoute) MatchInclude(req *http.Request) bool {
	path := req.URL.Path
	if r.Path != "/" {
		path = strings.TrimPrefix(path, r.Path)
	}
	if !r.Includes.Match(path) {
		return false
	}
	if r.Excludes.Match(path) {
		return false
	}
	return true
}

func (r *AggregateRoute) MatchAuth(req *http.Request) bool {
	path := req.URL.Path
	if r.Path != "/" {
		path = strings.TrimPrefix(path, r.Path)
	}
	if !r.Auth.Includes.Match(path) {
		return false
	}
	if r.Auth.Excludes.Match(path) {
		return false
	}
	return true
}
