package contexes_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestContexes(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Contexes Suite")
}
