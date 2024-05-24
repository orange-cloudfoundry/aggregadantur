package aggregadantur_test

import (
	"github.com/gorilla/sessions"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/orange-cloudfoundry/aggregadantur/contexes"
	"github.com/orange-cloudfoundry/aggregadantur/models"
	"github.com/orange-cloudfoundry/aggregadantur/testhelper"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/orange-cloudfoundry/aggregadantur"
)

var _ = Describe("AuthHandler", func() {
	var aggrRoute *models.AggregateRoute
	var upstreamHandler *TestHandler
	var packAuth *ServerPack
	var respRecorder *httptest.ResponseRecorder
	var authHandler *aggregadantur.AuthHandler
	var jwtToken string
	var store sessions.Store
	BeforeEach(func() {
		store = sessions.NewCookieStore([]byte("secret"))
		var err error
		respRecorder = httptest.NewRecorder()
		upstreamHandler = NewTestHandlerWithInterface(
			models.AggregateEndpoint{
				Url:        "http://localhost",
				Identifier: "test",
			},
		)

		packAuth = NewPack()
		scopes := []string{"openid", "admin"}
		jwtToken = GenerateJWTToken("user", scopes)
		accessResp := aggregadantur.AccessTokenResponse{
			AccessToken: jwtToken,
			TokenType:   "bearer",
			ExpiresIn:   time.Now().Add(5 * time.Minute).Second(),
			Scope:       strings.Join(scopes, " "),
		}
		packAuth.handler.SetInterface(accessResp)
		aggrRoute, err = models.NewAggregateRoute(
			"test",
			"test",
			models.NewUpstreamFromHandler(upstreamHandler),
			models.AggregateEndpoints{
				{
					Url:        "http://localhost",
					Identifier: "test",
				},
			},
			models.Auth{
				Includes: models.PathMatchers{models.NewPathMatcher("/**")},
				Excludes: models.PathMatchers{models.NewPathMatcher("/metrics")},
				Oauth2Auth: models.NewOauth2Auth(
					packAuth.HttpServer().URL,
					"cf",
					"",
					[]string{"admin"},
				),
				JWTCheck: models.JWTChecks{
					models.JWTCheck{
						Alg:               "RS256",
						Secret:            publicKeyJwt,
						Issuer:            "http://uaa.localhost",
						NotVerifyIssuedAt: false,
					},
				},
				LoginPageTemplate:     "",
				LoginPageTemplatePath: "",
			},
			models.PathMatchers{models.NewPathMatcher("/**")},
			models.PathMatchers{models.NewPathMatcher("/metrics")},
		)

		Expect(err).NotTo(HaveOccurred())
		authHandler = aggregadantur.NewAuthHandler(upstreamHandler, aggrRoute, http.DefaultClient, store)
	})
	AfterEach(func() {
		packAuth.HttpServer().Close()
	})

	Context("ServeHTTP", func() {
		When("have a options request", func() {
			It("should pass as it is to next handler by default", func() {
				req := testhelper.NewRequest(http.MethodOptions, "http://localhost", nil)

				authHandler.ServeHTTP(respRecorder, req)

				res := RespRecordToAggrEndpoint(respRecorder)
				Expect(res.Url).To(Equal("http://localhost"))
				Expect(res.Identifier).To(Equal("test"))
			})
		})
		When("not match auth", func() {
			It("should pass as it is to next handler by default", func() {
				req := testhelper.NewRequest(http.MethodGet, "http://localhost/metrics", nil)

				authHandler.ServeHTTP(respRecorder, req)

				res := RespRecordToAggrEndpoint(respRecorder)
				Expect(res.Url).To(Equal("http://localhost"))
				Expect(res.Identifier).To(Equal("test"))
			})
		})
		Context("No jwt given", func() {
			It("should give the login page on get request", func() {
				req := testhelper.NewRequest(http.MethodGet, "http://localhost", nil)
				auth := aggrRoute.Auth
				auth.LoginPageTemplate = "%s: %s"
				aggrRoute.Auth = auth

				authHandler.ServeHTTP(respRecorder, req)

				Expect(respRecorder.Code).To(Equal(http.StatusUnauthorized))
				Expect(respRecorder.Body.String()).To(Equal("Test: /"))
			})
			When("Post username and password from login page", func() {
				It("should set session and redirect if user is correct", func() {
					form := url.Values{}
					form.Add("username", "user")
					form.Add("password", "password")
					req := testhelper.NewRequest(http.MethodPost, "http://localhost", strings.NewReader(form.Encode()))
					req.Form = form
					req.PostForm = form
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

					authHandler.ServeHTTP(respRecorder, req)

					sess, err := store.Get(req, "auth-test")
					Expect(err).ToNot(HaveOccurred())
					Expect(sess.Values).To(HaveLen(1))
					Expect(sess.Values["jwt_token"]).To(Equal(jwtToken))
					Expect(respRecorder.Code).To(Equal(http.StatusTemporaryRedirect))
					Expect(respRecorder.Header().Get("Location")).To(Equal("/"))
				})

				It("should be unauthorized if user is incorrect", func() {
					form := url.Values{}
					form.Add("username", "user")
					form.Add("password", "password")
					req := testhelper.NewRequest(http.MethodPost, "http://localhost", strings.NewReader(form.Encode()))
					req.Form = form
					req.PostForm = form
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					packAuth.handler.SetFn(func(w http.ResponseWriter, req *http.Request) bool {
						w.WriteHeader(http.StatusUnauthorized)
						w.Write([]byte("user doesn't exists"))
						return true
					})

					authHandler.ServeHTTP(respRecorder, req)

					sess, err := store.Get(req, "auth-test")
					Expect(err).ToNot(HaveOccurred())
					Expect(sess.Values).To(HaveLen(0))
					Expect(respRecorder.Code).To(Equal(http.StatusUnauthorized))
				})
			})
		})
		Context("Token jwt is given", func() {
			It("should pass request and apply headers and contexts in request if token is correct", func() {
				req := testhelper.NewRequest(http.MethodGet, "http://localhost", nil)
				req.Header.Set("Authorization", "Bearer "+jwtToken)

				authHandler.ServeHTTP(respRecorder, req)

				res := RespRecordToAggrEndpoint(respRecorder)
				Expect(res.Url).To(Equal("http://localhost"))
				Expect(res.Identifier).To(Equal("test"))
				Expect(req.Header.Get(aggregadantur.XAggregatorUsernameHeader)).To(Equal("user"))
				Expect(req.Header.Get(aggregadantur.XAggregatorScopesHeader)).To(Equal("openid,admin"))
				Expect(contexes.Username(req)).To(Equal("user"))
				Expect(contexes.Scopes(req)).To(ConsistOf("openid", "admin"))
				Expect(contexes.JwtClaim(req).Username).To(Equal("user"))
				Expect(contexes.JwtClaim(req).Scope).To(ConsistOf("openid", "admin"))
			})
			It("should unauthorized if token is incorrect", func() {
				req := testhelper.NewRequest(http.MethodGet, "http://localhost", nil)
				req.Header.Set("Authorization", "Bearer "+jwtToken+"incorrect")

				authHandler.ServeHTTP(respRecorder, req)

				Expect(respRecorder.Code).To(Equal(http.StatusUnauthorized))
			})
			When("token is in session", func() {
				It("should pass request and apply headers and contexts in request if token is correct", func() {
					req := testhelper.NewRequest(http.MethodGet, "http://localhost", nil)
					sess, err := store.Get(req, "auth-test")
					Expect(err).ToNot(HaveOccurred())
					sess.Values["jwt_token"] = jwtToken
					err = sess.Save(req, httptest.NewRecorder())
					Expect(err).ToNot(HaveOccurred())

					authHandler.ServeHTTP(respRecorder, req)

					res := RespRecordToAggrEndpoint(respRecorder)
					Expect(res.Url).To(Equal("http://localhost"))
					Expect(res.Identifier).To(Equal("test"))
					Expect(req.Header.Get(aggregadantur.XAggregatorUsernameHeader)).To(Equal("user"))
					Expect(req.Header.Get(aggregadantur.XAggregatorScopesHeader)).To(Equal("openid,admin"))
					Expect(contexes.Username(req)).To(Equal("user"))
					Expect(contexes.Scopes(req)).To(ConsistOf("openid", "admin"))
					Expect(contexes.JwtClaim(req).Username).To(Equal("user"))
					Expect(contexes.JwtClaim(req).Scope).To(ConsistOf("openid", "admin"))
				})
			})

		})
	})

})
