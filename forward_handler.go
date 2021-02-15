package aggregadantur

import (
	"crypto/tls"
	"github.com/orange-cloudfoundry/aggregadantur/models"
	log "github.com/sirupsen/logrus"
	"github.com/vulcand/oxy/buffer"
	"github.com/vulcand/oxy/forward"
	"net"
	"net/http"
	"time"
)

type ForwardHandler struct {
	aggrRoute      *models.AggregateRoute
	reverseHandler http.Handler
}

func NewForwardHandler(aggrRoute *models.AggregateRoute) (*ForwardHandler, error) {
	reverseHandler, err := createReverseHandler(aggrRoute)
	if err != nil {
		return nil, err
	}
	return &ForwardHandler{
		aggrRoute:      aggrRoute,
		reverseHandler: reverseHandler,
	}, nil
}

func (f ForwardHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	f.aggrRoute.InjectForwardUrl(req)
	f.reverseHandler.ServeHTTP(w, req)
}

func createReverseHandler(proxyRoute *models.AggregateRoute) (http.Handler, error) {
	transport := &http.Transport{
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
			InsecureSkipVerify: proxyRoute.InsecureSkipVerify,
		},
	}
	entry := log.WithField("route_name", proxyRoute.Name)
	var err error
	var fwd *forward.Forwarder
	if !proxyRoute.NoBuffer {
		entry.Debug("orange-cloudfoundry/aggregadantur/proxy: Handler for routes will use buffer.")
		fwd, err = forward.New(forward.RoundTripper(transport))
	} else {
		entry.Debug("orange-cloudfoundry/aggregadantur/proxy: Handler for routes will use direct stream.")
		fwd, err = forward.New(forward.RoundTripper(transport), forward.Stream(true))
	}

	if err != nil {
		return nil, err
	}
	if proxyRoute.NoBuffer {
		return fwd, nil
	}
	return buffer.New(fwd, buffer.Retry(`IsNetworkError() && Attempts() < 2`))
}
