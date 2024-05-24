package models_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/orange-cloudfoundry/aggregadantur/models"
)

var _ = Describe("Matcher", func() {
	Context("PathMatcher", func() {
		It("should match /**", func() {
			matcher := models.NewPathMatcher("/**")
			Expect(matcher.Match("/firstlevel")).Should(BeTrue())
			Expect(matcher.Match("/firstlevel/secondlevel")).Should(BeTrue())
		})
		It("should match /*", func() {
			matcher := models.NewPathMatcher("/*")
			Expect(matcher.Match("/app")).Should(BeTrue())
			Expect(matcher.Match("/app/secondlevel")).Should(BeFalse())
		})
		It("should not match /app/*", func() {
			matcher := models.NewPathMatcher("/app/*")
			Expect(matcher.Match("/foo")).Should(BeFalse())
			Expect(matcher.Match("/app")).Should(BeTrue())
			Expect(matcher.Match("/app/secondlevel")).Should(BeTrue())
			Expect(matcher.Match("/app/secondlevel/thirdlevel")).Should(BeFalse())
		})
		It("should not match /app/**", func() {
			matcher := models.NewPathMatcher("/app/**")
			Expect(matcher.Match("/foo")).Should(BeFalse())
			Expect(matcher.Match("/app")).Should(BeTrue())
			Expect(matcher.Match("/app/secondlevel")).Should(BeTrue())
			Expect(matcher.Match("/app/secondlevel/thirdlevel")).Should(BeTrue())
		})
		It("should not match /*/app", func() {
			Expect(func() { models.NewPathMatcher("/*/app") }).Should(Panic())
		})
		It("should not match /app/***", func() {
			Expect(func() { models.NewPathMatcher("/app/***") }).Should(Panic())
		})
	})
	Context("PathMatchers", func() {
		It("should match if one of path matcher match", func() {
			matchers := models.PathMatchers{
				models.NewPathMatcher("/foo/**"),
				models.NewPathMatcher("/app/**"),
			}
			Expect(matchers.Match("/app")).Should(BeTrue())
		})
		It("should not match if none path matcher match", func() {
			matchers := models.PathMatchers{
				models.NewPathMatcher("/foo/**"),
				models.NewPathMatcher("/app/**"),
			}
			Expect(matchers.Match("/none")).Should(BeFalse())
		})
	})
})
