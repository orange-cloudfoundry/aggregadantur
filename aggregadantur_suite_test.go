package aggregadantur_test

import (
	"bytes"
	"encoding/json"
	"github.com/golang-jwt/jwt/v4"
	"github.com/orange-cloudfoundry/aggregadantur/jwtclaim"
	"github.com/orange-cloudfoundry/aggregadantur/models"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestAggregadantur(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Aggregadantur Suite")
}

var privateKeyJwt = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtn
SgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0i
cqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhC
PUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsAR
ap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKA
Rdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3
n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAy
MaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9
POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdE
KdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gM
IvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDn
FcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvY
mEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghj
FuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+U
I5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs
2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn
/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNT
OvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86
EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+
hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL0
4aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckb
mDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ry
eBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3
CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+
9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq
-----END RSA PRIVATE KEY-----
`

var publicKeyJwt = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7
mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBp
HssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2
XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3b
ODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy
7wIDAQAB
-----END PUBLIC KEY-----
`

type ServerPack struct {
	aggregateEndpoint models.AggregateEndpoint
	handler           *TestHandler
	httpServer        *httptest.Server
}

func NewAggregateEndpointPack(identifier string) *ServerPack {

	handler := NewTestHandler()
	httpServer := httptest.NewServer(handler)
	aggrEndpoint := models.AggregateEndpoint{
		Url:        httpServer.URL,
		Identifier: identifier,
	}
	handler.SetInterface(aggrEndpoint)
	return &ServerPack{
		aggregateEndpoint: aggrEndpoint,
		handler:           handler,
		httpServer:        httpServer,
	}
}

func NewPack() *ServerPack {
	handler := NewTestHandler()
	httpServer := httptest.NewServer(handler)
	handler.SetContent("empty.")
	return &ServerPack{
		handler:    handler,
		httpServer: httpServer,
	}
}

func (a *ServerPack) HttpServer() *httptest.Server {
	return a.httpServer
}

func (a *ServerPack) Handler() *TestHandler {
	return a.handler
}

func (a *ServerPack) AggregateEndpoint() models.AggregateEndpoint {
	return a.aggregateEndpoint
}

type TestHandler struct {
	content *bytes.Buffer
	status  int
	fn      func(w http.ResponseWriter, req *http.Request) bool
}

func NewTestHandler() *TestHandler {
	return &TestHandler{
		content: &bytes.Buffer{},
		status:  200,
	}
}

func NewTestHandlerWithContent(content string) *TestHandler {
	return &TestHandler{
		content: bytes.NewBufferString(content),
		status:  200,
	}
}

func NewTestHandlerWithInterface(content interface{}) *TestHandler {
	b, err := json.Marshal(content)
	Expect(err).NotTo(HaveOccurred())
	return &TestHandler{
		content: bytes.NewBuffer(b),
		status:  200,
	}
}

func NewTestHandlerWithFunc(fn func(w http.ResponseWriter, req *http.Request) bool) *TestHandler {
	return &TestHandler{
		content: bytes.NewBufferString("empty."),
		status:  200,
		fn:      fn,
	}
}

func (t *TestHandler) SetStatus(status int) {
	t.status = status
}

func (t *TestHandler) SetBytes(content []byte) {
	t.content.Reset()
	t.content.Write(content)
}

func (t *TestHandler) SetContent(content string) {
	t.content.Reset()
	t.content.WriteString(content)
}

func (t *TestHandler) SetInterface(content interface{}) {
	t.content.Reset()
	b, err := json.Marshal(content)
	Expect(err).NotTo(HaveOccurred())
	t.SetBytes(b)
}

func (t *TestHandler) SetFn(fn func(w http.ResponseWriter, req *http.Request) bool) {
	t.fn = fn
}

func (t TestHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if t.fn != nil {
		stop := t.fn(w, req)
		if stop {
			return
		}
	}

	w.WriteHeader(t.status)
	w.Write(t.content.Bytes())
}

func RespRecordToAggrEndpoint(respRecorder *httptest.ResponseRecorder) models.AggregateEndpoint {
	var res models.AggregateEndpoint
	err := json.Unmarshal(respRecorder.Body.Bytes(), &res)
	Expect(err).NotTo(HaveOccurred())
	return res
}

func RespRecordToAggrEndpoints(respRecorder *httptest.ResponseRecorder) map[string]models.AggregateEndpoint {
	res := make(map[string]models.AggregateEndpoint)
	err := json.Unmarshal(respRecorder.Body.Bytes(), &res)
	Expect(err).NotTo(HaveOccurred())
	return res
}

func GenerateJWTToken(username string, scopes []string) string {
	key, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyJwt))
	method := jwt.SigningMethodRS256
	tok := jwt.New(method)
	tok.Claims = jwtclaim.ScopeClaims{
		Username:  username,
		Audience:  []string{"aggregadantur"},
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Id:        "an-id",
		IssuedAt:  time.Now().Unix(),
		Issuer:    "http://uaa.localhost",
		NotBefore: time.Now().Add(-5 * time.Minute).Unix(),
		Subject:   "a-subject",
		Scope:     scopes,
	}

	strSign, err := tok.SigningString()
	if err != nil {
		Expect(err).NotTo(HaveOccurred())
	}
	sig, err := method.Sign(strSign, key)
	if err != nil {
		Expect(err).NotTo(HaveOccurred())
	}

	return strSign + "." + sig
}
