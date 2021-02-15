package aggregadantur_test

import (
	"bytes"
	"encoding/json"
	"github.com/orange-cloudfoundry/aggregadantur/models"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestAggregadantur(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Aggregadantur Suite")
}

type AggregateEndpointPack struct {
	aggregateEndpoint models.AggregateEndpoint
	handler           *TestHandler
	httpServer        *httptest.Server
}

func NewAggregateEndpointPack(identifier string) *AggregateEndpointPack {

	handler := NewTestHandler()
	httpServer := httptest.NewServer(handler)
	aggrEndpoint := models.AggregateEndpoint{
		Url:        httpServer.URL,
		Identifier: identifier,
	}
	handler.SetInterface(aggrEndpoint)
	return &AggregateEndpointPack{
		aggregateEndpoint: aggrEndpoint,
		handler:           handler,
		httpServer:        httptest.NewServer(handler),
	}
}

func (a *AggregateEndpointPack) HttpServer() *httptest.Server {
	return a.httpServer
}

func (a *AggregateEndpointPack) Handler() *TestHandler {
	return a.handler
}

func (a *AggregateEndpointPack) AggregateEndpoint() models.AggregateEndpoint {
	return a.aggregateEndpoint
}

type TestHandler struct {
	content *bytes.Buffer
	status  int
	fn      func(w http.ResponseWriter, req *http.Request)
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

func (t *TestHandler) SetFn(fn func(w http.ResponseWriter, req *http.Request)) {
	t.fn = fn
}

func (t TestHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if t.fn != nil {
		t.fn(w, req)
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
