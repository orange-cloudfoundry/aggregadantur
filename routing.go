package aggregadantur

import (
	"crypto/tls"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/orange-cloudfoundry/aggregadantur/models"
	log "github.com/sirupsen/logrus"
	"github.com/vulcand/oxy/trace"
	"net"
	"net/http"
	"strings"
	"time"
)

type Router struct {
	rtr    *mux.Router
	store  sessions.Store
	tracer bool
}

func NewRouter(store sessions.Store) *Router {
	return &Router{
		rtr:    mux.NewRouter(),
		store:  store,
		tracer: true,
	}
}

func (r Router) DisableTracer() {
	r.tracer = false
}

func (r Router) AddMuxRoute(route *models.AggregateRoute) error {
	httpClient := makeHttpClient(route.InsecureSkipVerify)
	var handler http.Handler
	var err error
	if route.Upstream.Handler != nil {
		handler = route.Upstream.Handler
	} else {
		handler, err = NewForwardHandler(route)
		if err != nil {
			return err
		}
	}

	handler = NewAggregateHandler(handler, route, httpClient)
	handler = NewAuthHandler(handler, route, httpClient, r.store)
	if r.tracer {
		handler, err = trace.New(handler, log.StandardLogger().Out)
	}

	if err != nil {
		return err
	}
	r.rtr.NewRoute().
		Name(route.Name).
		MatcherFunc(func(req *http.Request, match *mux.RouteMatch) bool {
			if route.Path != "/" && !strings.HasPrefix(req.URL.Path, route.Path) {
				return false
			}
			return route.Hosts.Match(req.Host)
		}).Handler(handler)

	return nil
}

func (r Router) AddMuxRoutes(routes ...*models.AggregateRoute) error {
	for _, route := range routes {
		err := r.AddMuxRoute(route)
		if err != nil {
			return fmt.Errorf("Error when adding route %s: %s", route.Name, err.Error())
		}
	}
	return nil
}

func (r Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.rtr.ServeHTTP(w, req)
}

func makeHttpClient(skipSSLValidation bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipSSLValidation,
			},
		},
	}
}
