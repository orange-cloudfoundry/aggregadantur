package aggregadantur_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/orange-cloudfoundry/aggregadantur"
	"github.com/orange-cloudfoundry/aggregadantur/models"
	"github.com/orange-cloudfoundry/aggregadantur/testhelper"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("ForwardHandler", func() {
	var pack *ServerPack
	var respRecorder *httptest.ResponseRecorder
	var aggrRoute *models.AggregateRoute
	var fwdHandler *aggregadantur.ForwardHandler
	BeforeEach(func() {
		log.StandardLogger().Out = io.Discard
		var err error
		respRecorder = httptest.NewRecorder()
		pack = NewAggregateEndpointPack("test")
		aggrRoute, err = models.NewAggregateRoute(
			"test",
			"test",
			models.NewUpstreamFromUrl(pack.HttpServer().URL),
			models.AggregateEndpoints{
				{
					Url:        "http://localhost",
					Identifier: "test",
				},
			},
			models.Auth{},
			models.PathMatchers{models.NewPathMatcher("/**")},
			models.PathMatchers{models.NewPathMatcher("/metrics")},
		)
		Expect(err).NotTo(HaveOccurred())
		fwdHandler, err = aggregadantur.NewForwardHandler(aggrRoute)
		Expect(err).NotTo(HaveOccurred())
	})
	AfterEach(func() {
		log.StandardLogger().Out = os.Stdout
		pack.HttpServer().Close()
	})
	Context("ServeHTTP", func() {
		It("should forward to with retry by default", func() {
			req := testhelper.NewRequest(http.MethodGet, "http://localhost", bytes.NewBufferString("empty."))
			nbTry := 0
			pack.Handler().SetFn(func(w http.ResponseWriter, req *http.Request) bool {
				nbTry += 1
				if nbTry == 2 {
					w.WriteHeader(http.StatusCreated)
					_, err := w.Write([]byte("good"))
					if err != nil {
						panic(err)
					}
					return true
				}
				w.WriteHeader(http.StatusBadGateway)
				_, err := w.Write([]byte("bad"))
				if err != nil {
					panic(err)
				}
				return true
			})

			fwdHandler.ServeHTTP(respRecorder, req)

			Expect(nbTry).To(Equal(2))
			Expect(respRecorder.Code).To(Equal(http.StatusCreated))
			Expect(respRecorder.Body.String()).To(Equal("good"))
		})
		When("no buffer is set on route", func() {
			It("Should forward without retry and full stream", func() {
				aggrRoute.NoBuffer = true
				fwdHandler, _ = aggregadantur.NewForwardHandler(aggrRoute)
				req := testhelper.NewRequest(http.MethodGet, "http://localhost", bytes.NewBufferString("empty."))
				nbTry := 0
				pack.Handler().SetFn(func(w http.ResponseWriter, req *http.Request) bool {
					nbTry += 1
					if nbTry == 2 {
						w.WriteHeader(http.StatusCreated)
						_, err := w.Write([]byte("good"))
						if err != nil {
							panic(err)
						}
						return true
					}
					w.WriteHeader(http.StatusBadGateway)
					_, err := w.Write([]byte("bad"))
					if err != nil {
						panic(err)
					}
					return true
				})

				fwdHandler.ServeHTTP(respRecorder, req)

				Expect(nbTry).To(Equal(1))
				Expect(respRecorder.Code).To(Equal(http.StatusBadGateway))
				Expect(respRecorder.Body.String()).To(Equal("bad"))
			})
		})
	})
})
