package models_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"

	"github.com/orange-cloudfoundry/aggregadantur/models"
)

var _ = Describe("AggregateRoute", func() {
	var aggrRoute *models.AggregateRoute
	BeforeEach(func() {
		var err error
		aggrRoute, err = models.NewAggregateRoute(
			"test",
			"test",
			models.NewUpstreamFromUrl("https://test"),
			models.AggregateEndpoints{
				{
					Url:        "http://localhost",
					Identifier: "test",
				},
				{
					Url:        "http://test2",
					Identifier: "test2",
				},
				{
					Url:        "http://test3",
					Identifier: "test3",
				},
			},
			models.Auth{},
			models.PathMatchers{models.NewPathMatcher("/**")},
			models.PathMatchers{models.NewPathMatcher("/metrics")},
		)
		Expect(err).NotTo(HaveOccurred())
	})

	Context("Check", func() {
		It("should create error when name or identifier is empty", func() {
			aggrRoute.Name = ""
			err := aggrRoute.Check()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("name"))

			aggrRoute.Name = "foo"
			aggrRoute.Identifier = ""
			err = aggrRoute.Check()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("identifier"))
		})

	})
	Context("InjectForwardUrl", func() {
		When("Upstream is an http handler", func() {
			It("should inject context to identify that's http handled route", func() {
				req, err := http.NewRequest(http.MethodGet, "http://localhost", nil)
				Expect(err).NotTo(HaveOccurred())

				aggrRoute.Upstream = models.NewUpstreamFromHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {

				}))
				aggrRoute.InjectForwardUrl(req)

				isHandler := req.Context().Value(models.IsHandlerContextUpstream)
				Expect(isHandler).To(BeTrue())
			})
		})
		When("Upstream is an url", func() {
			It("should set scheme and host from upstream", func() {
				req, err := http.NewRequest(http.MethodGet, "http://localhost/foo", nil)
				Expect(err).NotTo(HaveOccurred())

				aggrRoute.InjectForwardUrl(req)

				Expect(req.URL.String()).To(Equal("https://test/foo"))
				Expect(req.RequestURI).To(Equal("/foo"))
			})
			When("Aggregate route has prefix path", func() {
				It("should set scheme and host from upstream and remove path prefix", func() {
					aggrRoute.Path = "/begin"
					req, err := http.NewRequest(http.MethodGet, "http://localhost/begin/foo", nil)
					Expect(err).NotTo(HaveOccurred())

					aggrRoute.InjectForwardUrl(req)

					Expect(req.URL.String()).To(Equal("https://test/foo"))
					Expect(req.RequestURI).To(Equal("/foo"))
				})
			})
			When("Aggregate route has basic auth user in upstream url", func() {
				It("should set basic auth in request", func() {
					aggrRoute.Upstream = models.NewUpstreamFromUrl("https://user:password@test")
					req, err := http.NewRequest(http.MethodGet, "http://localhost/foo", nil)
					Expect(err).NotTo(HaveOccurred())

					aggrRoute.InjectForwardUrl(req)

					Expect(req.Header.Get("Authorization")).To(Equal("Basic dXNlcjpwYXNzd29yZA=="))
				})
			})
			When("Aggregate route has default query params", func() {
				It("should set query params in addition of previous one", func() {
					aggrRoute.Upstream = models.NewUpstreamFromUrl("https://test?param=value")
					req, err := http.NewRequest(http.MethodGet, "http://localhost/foo?current=value2", nil)
					Expect(err).NotTo(HaveOccurred())

					aggrRoute.InjectForwardUrl(req)

					Expect(req.URL.Query().Get("current")).To(Equal("value2"))
					Expect(req.URL.Query().Get("param")).To(Equal("value"))
				})
			})
		})
	})
	Context("InjectByEndpoint", func() {
		When("Identifier is equal to current route identifier", func() {
			It("should only inject forward url", func() {
				req, err := http.NewRequest(http.MethodGet, "http://localhost/foo", nil)
				Expect(err).NotTo(HaveOccurred())

				aggrRoute.InjectByEndpoint(req, models.AggregateEndpoint{
					Url:        "https://test",
					Identifier: "test",
				})

				Expect(req.URL.String()).To(Equal("https://test/foo"))
				// request uri should be empty as it is a request for a client http not for http server
				Expect(req.RequestURI).To(Equal(""))
			})
		})
		When("Aggregate route has prefix path", func() {
			It("should set scheme and host from aggregate endpoint and remove path prefix", func() {
				aggrRoute.Path = "/begin"
				req, err := http.NewRequest(http.MethodGet, "http://localhost/begin/foo", nil)
				Expect(err).NotTo(HaveOccurred())

				aggrRoute.InjectByEndpoint(req, models.AggregateEndpoint{
					Url:        "https://test2",
					Identifier: "test2",
				})

				Expect(req.URL.String()).To(Equal("https://test2/foo"))
			})
		})

		When("Aggregate endpoint has prefix path", func() {
			It("should prefix request path with aggregate endpoint path", func() {
				req, err := http.NewRequest(http.MethodGet, "http://localhost/foo", nil)
				Expect(err).NotTo(HaveOccurred())

				aggrRoute.InjectByEndpoint(req, models.AggregateEndpoint{
					Url:        "https://test2/begin",
					Identifier: "test2",
				})

				Expect(req.URL.String()).To(Equal("https://test2/begin/foo"))
			})
		})

		When("Aggregate endpoint has basic auth", func() {
			It("should prefix request path with aggregate endpoint path", func() {
				req, err := http.NewRequest(http.MethodGet, "http://localhost/foo", nil)
				Expect(err).NotTo(HaveOccurred())

				aggrRoute.InjectByEndpoint(req, models.AggregateEndpoint{
					Url:        "https://user:password@test2",
					Identifier: "test2",
				})

				Expect(req.Header.Get("Authorization")).To(Equal("Basic dXNlcjpwYXNzd29yZA=="))
			})
		})
		When("Aggregate endpoint has default query param", func() {
			It("should set query params in addition of previous one", func() {
				req, err := http.NewRequest(http.MethodGet, "http://localhost/foo?current=value2", nil)
				Expect(err).NotTo(HaveOccurred())

				aggrRoute.InjectByEndpoint(req, models.AggregateEndpoint{
					Url:        "https://user:password@test2?param=value",
					Identifier: "test2",
				})

				Expect(req.URL.Query().Get("current")).To(Equal("value2"))
				Expect(req.URL.Query().Get("param")).To(Equal("value"))
			})
		})
	})
	Context("MatchInclude", func() {
		It("should accept req which is included", func() {
			req, err := http.NewRequest(http.MethodGet, "http://localhost/", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(aggrRoute.MatchInclude(req)).To(BeTrue())
		})
		It("should deny req which is not included", func() {
			aggrRoute.Includes = models.PathMatchers{models.NewPathMatcher("/foo")}

			req, err := http.NewRequest(http.MethodGet, "http://localhost/bar", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(aggrRoute.MatchInclude(req)).To(BeFalse())
		})
		It("should accept req which is included and also in exclude", func() {
			req, err := http.NewRequest(http.MethodGet, "http://localhost/metrics", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(aggrRoute.MatchInclude(req)).To(BeFalse())
		})
	})

	Context("MatchAuth", func() {
		It("should accept req which is included", func() {
			aggrRoute.Auth.Includes = models.PathMatchers{models.NewPathMatcher("/**")}

			req, err := http.NewRequest(http.MethodGet, "http://localhost/", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(aggrRoute.MatchAuth(req)).To(BeTrue())
		})
		It("should deny req which is not included", func() {
			aggrRoute.Auth.Includes = models.PathMatchers{models.NewPathMatcher("/foo")}

			req, err := http.NewRequest(http.MethodGet, "http://localhost/bar", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(aggrRoute.MatchAuth(req)).To(BeFalse())
		})
		It("should accept req which is included and also in exclude", func() {
			aggrRoute.Auth.Includes = models.PathMatchers{models.NewPathMatcher("/**")}
			aggrRoute.Auth.Excludes = models.PathMatchers{models.NewPathMatcher("/metrics")}
			req, err := http.NewRequest(http.MethodGet, "http://localhost/metrics", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(aggrRoute.MatchAuth(req)).To(BeFalse())
		})
	})
	Context("IsMethodAllowedMethod", func() {
		It("should accept only GET method when not set", func() {
			reqGet, err := http.NewRequest(http.MethodGet, "http://localhost/metrics", nil)
			Expect(err).NotTo(HaveOccurred())
			reqPost, err := http.NewRequest(http.MethodPost, "http://localhost/metrics", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(aggrRoute.IsMethodAllowedMethod(reqGet)).To(BeTrue())
			Expect(aggrRoute.IsMethodAllowedMethod(reqPost)).To(BeFalse())
		})

		It("should accept accept methods defined by user", func() {
			aggrRoute.AllowedMethods = []string{http.MethodPost, http.MethodGet}

			reqGet, err := http.NewRequest(http.MethodGet, "http://localhost/metrics", nil)
			Expect(err).NotTo(HaveOccurred())
			reqPost, err := http.NewRequest(http.MethodPost, "http://localhost/metrics", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(aggrRoute.IsMethodAllowedMethod(reqGet)).To(BeTrue())
			Expect(aggrRoute.IsMethodAllowedMethod(reqPost)).To(BeTrue())
		})
	})
})
