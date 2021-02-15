package contexes_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/orange-cloudfoundry/aggregadantur/contexes"
	"github.com/orange-cloudfoundry/aggregadantur/testhelper"
	"net/http"
)

var _ = Describe("Helper", func() {

	Context("AddContextValue", func() {
		It("should add a context value in current request", func() {
			req := testhelper.NewRequest(http.MethodGet, "http://localhost", nil)

			contexes.AddContextValue(req, "foo", "bar")

			Expect(req.Context().Value("foo").(string)).To(Equal("bar"))
		})
	})

	Context("GetContextValue", func() {
		It("should get context value from current request", func() {
			req := testhelper.NewRequest(http.MethodGet, "http://localhost", nil)

			contexes.AddContextValue(req, "foo", "bar")
			val := contexes.GetContextValue(req, "foo", "")

			Expect(val).To(Equal("bar"))
		})
		It("should give default value if key not found in request", func() {
			req := testhelper.NewRequest(http.MethodGet, "http://localhost", nil)

			val := contexes.GetContextValue(req, "foo", 2)

			Expect(val).To(Equal(2))
		})
	})
})
