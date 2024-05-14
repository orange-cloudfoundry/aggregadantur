package main

import (
	"crypto/tls"
	"github.com/alecthomas/kingpin/v2"
	"github.com/gorilla/sessions"
	"github.com/orange-cloudfoundry/aggregadantur"
	"github.com/prometheus/common/version"
	log "github.com/sirupsen/logrus"
	"net"
	"net/http"
	"time"
)

var (
	configFile = kingpin.Flag("config", "Configuration File").Short('c').Default("config.yml").String()
)

func main() {
	kingpin.Version(version.Print("aggregadantur"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	c, err := GetConfig(*configFile)
	if err != nil {
		log.Fatal("Error loading config: ", err.Error())
		return
	}

	sess := sessions.NewCookieStore([]byte(c.Server.SessionKey))
	router := aggregadantur.NewRouter(sess)
	err = router.AddMuxRoutes(c.Routes...)
	if err != nil {
		log.Fatal("Error loading routes: ", err.Error())
		return
	}
	srv := &http.Server{
		Handler: router,
		Addr:    c.Server.Listen,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	listener, err := makeListener(c)
	if err != nil {
		log.Fatal(err.Error())
		return
	}
	log.Fatal(srv.Serve(listener))
}

func makeListener(c Config) (net.Listener, error) {
	listenAddr := c.Server.Listen
	if !c.Server.EnableSSL {
		log.Infof("Listen %s without tls ...", listenAddr)
		return net.Listen("tcp", listenAddr)
	}
	log.Infof("Listen %s with tls ...", listenAddr)
	cert, caPool, err := c.Server.TLSPem.CertificateAndPool()
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(listener, tlsConfig), nil
}
