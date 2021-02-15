package testhelper

import (
	"github.com/onsi/gomega"
	"io"
	"net/http"
)

func NewRequest(method string, url string, body io.Reader) *http.Request {
	req, err := http.NewRequest(method, url, body)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return req
}
