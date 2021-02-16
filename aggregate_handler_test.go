package aggregadantur_test

import (
	"encoding/json"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/orange-cloudfoundry/aggregadantur"
	"github.com/orange-cloudfoundry/aggregadantur/contexes"
	"github.com/orange-cloudfoundry/aggregadantur/models"
	"github.com/orange-cloudfoundry/aggregadantur/testhelper"
	"net/http"
	"net/http/httptest"
)

var _ = Describe("AggregateHandler", func() {
	var aggrRoute *models.AggregateRoute
	var upstreamHandler *TestHandler
	var test2Pack *ServerPack
	var test3Pack *ServerPack
	var respRecorder *httptest.ResponseRecorder
	var aggrHandler *aggregadantur.AggregateHandler
	BeforeEach(func() {
		var err error
		respRecorder = httptest.NewRecorder()
		upstreamHandler = NewTestHandlerWithInterface(
			models.AggregateEndpoint{
				Url:        "http://localhost",
				Identifier: "test",
			},
		)

		test2Pack = NewAggregateEndpointPack("test2")
		test3Pack = NewAggregateEndpointPack("test3")
		aggrRoute, err = models.NewAggregateRoute(
			"test",
			"test",
			models.NewUpstreamFromHandler(upstreamHandler),
			models.AggregateEndpoints{
				{
					Url:        "http://localhost",
					Identifier: "test",
				},
				test2Pack.AggregateEndpoint(),
				test3Pack.AggregateEndpoint(),
			},
			models.Auth{},
			models.PathMatchers{models.NewPathMatcher("/**")},
			models.PathMatchers{models.NewPathMatcher("/metrics")},

		)

		Expect(err).NotTo(HaveOccurred())
		aggrHandler = aggregadantur.NewAggregateHandler(upstreamHandler, aggrRoute, http.DefaultClient)
	})
	AfterEach(func() {
		test2Pack.HttpServer().Close()
		test3Pack.HttpServer().Close()
	})
	Context("does not meet condition for doing aggregation", func() {
		It("should pass request as it is if not get request", func() {
			req := testhelper.NewRequest(http.MethodPost, "http://localhost", nil)

			aggrHandler.ServeHTTP(respRecorder, req)

			res := RespRecordToAggrEndpoint(respRecorder)
			Expect(res.Url).To(Equal("http://localhost"))
			Expect(res.Identifier).To(Equal("test"))
		})
		It("should pass request as it is if no aggregation mode set", func() {
			req := testhelper.NewRequest(http.MethodGet, "http://localhost", nil)

			aggrHandler.ServeHTTP(respRecorder, req)

			res := RespRecordToAggrEndpoint(respRecorder)
			Expect(res.Url).To(Equal("http://localhost"))
			Expect(res.Identifier).To(Equal("test"))
		})
		It("should pass request as it is if url not in includes", func() {
			req := testhelper.NewRequest(http.MethodGet, "http://localhost/metrics", nil)
			req.Header.Set(aggregadantur.XAggregatorModeHeader, string(aggregadantur.AggregateModeDefault))
			aggrHandler.ServeHTTP(respRecorder, req)

			res := RespRecordToAggrEndpoint(respRecorder)
			Expect(res.Url).To(Equal("http://localhost"))
			Expect(res.Identifier).To(Equal("test"))
		})
	})

	It("should aggregate if condition are met", func() {
		req := testhelper.NewRequest(http.MethodGet, "http://localhost/aggregate", nil)
		req.Header.Set(aggregadantur.XAggregatorModeHeader, string(aggregadantur.AggregateModeDefault))
		aggrHandler.ServeHTTP(respRecorder, req)

		res := RespRecordToAggrEndpoints(respRecorder)
		Expect(res["test"].Url).To(Equal("http://localhost"))
		Expect(res["test"].Identifier).To(Equal("test"))
		Expect(res["test2"].Identifier).To(Equal("test2"))
		Expect(res["test3"].Identifier).To(Equal("test3"))
	})
	It("should aggregate  if condition are met even if answer is not json", func() {
		req := testhelper.NewRequest(http.MethodGet, "http://localhost/aggregate", nil)
		req.Header.Set(aggregadantur.XAggregatorModeHeader, string(aggregadantur.AggregateModeDefault))
		upstreamHandler.SetContent("test")
		test2Pack.Handler().SetContent("test2")
		test3Pack.Handler().SetContent("test3")
		aggrHandler.ServeHTTP(respRecorder, req)

		res := make(map[string]string)
		err := json.Unmarshal(respRecorder.Body.Bytes(), &res)
		Expect(err).ToNot(HaveOccurred())
		Expect(res["test"]).To(Equal("test"))
		Expect(res["test2"]).To(Equal("test2"))
		Expect(res["test3"]).To(Equal("test3"))
	})
	When("aggregator_targets is set", func() {
		It("should give all targets targetted and not more", func() {
			req := testhelper.NewRequest(http.MethodGet, "http://localhost/aggregate", nil)
			req.Header.Set(aggregadantur.XAggregatorModeHeader, string(aggregadantur.AggregateModeDefault))
			req.Header.Set(aggregadantur.XAggregatorTargetsHeader, "test2,test3")
			aggrHandler.ServeHTTP(respRecorder, req)

			res := RespRecordToAggrEndpoints(respRecorder)
			Expect(res).Should(HaveLen(2))
			Expect(res["test2"].Identifier).To(Equal("test2"))
			Expect(res["test3"].Identifier).To(Equal("test3"))
		})
	})

	When("Authorization header is given", func() {
		It("Should be passed to all endpoints", func() {
			req := testhelper.NewRequest(http.MethodGet, "http://localhost/aggregate", nil)
			req.Header.Set(aggregadantur.XAggregatorModeHeader, string(aggregadantur.AggregateModeDefault))
			req.Header.Set("Authorization", "something")

			upstreamHandler.SetFn(func(w http.ResponseWriter, req *http.Request) bool {
				defer GinkgoRecover()
				Expect(req.Header.Get("Authorization")).To(Equal("something"))
				return false
			})
			test2Pack.Handler().SetFn(func(w http.ResponseWriter, req *http.Request) bool {
				defer GinkgoRecover()
				Expect(req.Header.Get("Authorization")).To(Equal("something"))
				return false
			})
			test3Pack.Handler().SetFn(func(w http.ResponseWriter, req *http.Request) bool {
				defer GinkgoRecover()
				Expect(req.Header.Get("Authorization")).To(Equal("something"))
				return false
			})

			aggrHandler.ServeHTTP(respRecorder, req)
		})
	})

	When("request has username in context", func() {
		It("Should be passed to all endpoints", func() {
			req := testhelper.NewRequest(http.MethodGet, "http://localhost/aggregate", nil)
			req.Header.Set(aggregadantur.XAggregatorModeHeader, string(aggregadantur.AggregateModeDefault))
			contexes.SetUsername(req, "user")

			upstreamHandler.SetFn(func(w http.ResponseWriter, req *http.Request) bool {
				defer GinkgoRecover()
				Expect(req.Header.Get(aggregadantur.XAggregatorUsernameHeader)).To(Equal("user"))
				return false
			})
			test2Pack.Handler().SetFn(func(w http.ResponseWriter, req *http.Request) bool {
				defer GinkgoRecover()
				Expect(req.Header.Get(aggregadantur.XAggregatorUsernameHeader)).To(Equal("user"))
				return false
			})
			test3Pack.Handler().SetFn(func(w http.ResponseWriter, req *http.Request) bool {
				defer GinkgoRecover()
				Expect(req.Header.Get(aggregadantur.XAggregatorUsernameHeader)).To(Equal("user"))
				return false
			})

			aggrHandler.ServeHTTP(respRecorder, req)
		})
	})

	When("request has scopes in context", func() {
		It("Should be passed to all endpoints", func() {
			req := testhelper.NewRequest(http.MethodGet, "http://localhost/aggregate", nil)
			req.Header.Set(aggregadantur.XAggregatorModeHeader, string(aggregadantur.AggregateModeDefault))
			contexes.SetScopes(req, []string{"openid", "admin"})

			upstreamHandler.SetFn(func(w http.ResponseWriter, req *http.Request) bool {
				defer GinkgoRecover()
				Expect(req.Header.Get(aggregadantur.XAggregatorScopesHeader)).To(Equal("openid,admin"))
				return false
			})
			test2Pack.Handler().SetFn(func(w http.ResponseWriter, req *http.Request) bool {
				defer GinkgoRecover()
				Expect(req.Header.Get(aggregadantur.XAggregatorScopesHeader)).To(Equal("openid,admin"))
				return false
			})
			test3Pack.Handler().SetFn(func(w http.ResponseWriter, req *http.Request) bool {
				defer GinkgoRecover()
				Expect(req.Header.Get(aggregadantur.XAggregatorScopesHeader)).To(Equal("openid,admin"))
				return false
			})

			aggrHandler.ServeHTTP(respRecorder, req)
		})
	})
})
