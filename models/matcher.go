package models

import (
	"encoding/json"
	"fmt"
	"github.com/gobwas/glob"
	"regexp"
)

const (
	PathRegex = "(?i)^((/[^/\\*]*)*)(/((\\*){1,2}))?$"
)

type PathMatchers []*PathMatcher

func (res PathMatchers) Match(path string) bool {
	for _, re := range res {
		if re.Match(path) {
			return true
		}
	}
	return false
}

type PathMatcher struct {
	pathMatcher *regexp.Regexp
	expr        string
	appPath     string
}

func NewPathMatcher(path string) *PathMatcher {
	err := checkPathMatcher(path)
	if err != nil {
		panic(err)
	}

	return &PathMatcher{
		pathMatcher: generatePathMatcher(path),
		expr:        path,
		appPath:     generateRawPath(path),
	}
}

func (re PathMatcher) String() string {
	return re.expr
}

func (re PathMatcher) AppPath() string {
	return re.appPath
}

func (re PathMatcher) CreateRoutePath(finalPath string) string {
	return re.appPath + finalPath
}

func (re PathMatcher) Match(path string) bool {
	return re.pathMatcher.MatchString(path)
}

func (re *PathMatcher) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return fmt.Errorf("when unmarshal path matcher: %s", err.Error())
	}
	err = re.Load(s)
	if err != nil {
		return fmt.Errorf("when unmarshal path matcher: %s", err.Error())
	}
	return nil
}

func (re *PathMatcher) UnmarshalCloud(data interface{}) error {
	return re.Load(data.(string))
}

func (re *PathMatcher) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return fmt.Errorf("when unmarshal path matcher: %s", err.Error())
	}
	err = re.Load(s)
	if err != nil {
		return fmt.Errorf("when unmarshal path matcher: %s", err.Error())
	}
	return nil
}

func (re *PathMatcher) Load(s string) error {
	err := checkPathMatcher(s)
	if err != nil {
		return err
	}
	re.pathMatcher = generatePathMatcher(s)
	re.expr = s
	re.appPath = generateRawPath(s)
	return nil
}

func checkPathMatcher(path string) error {
	reg := regexp.MustCompile(PathRegex)
	if !reg.MatchString(path) {
		return fmt.Errorf("Invalid path, e.g.: /api/** to match everything, /api/* to match first level or /api to only match this")
	}
	return nil
}

func generateRawPath(path string) string {
	reg := regexp.MustCompile(PathRegex)
	sub := reg.FindStringSubmatch(path)
	return sub[1]
}

func generatePathMatcher(path string) *regexp.Regexp {
	var pathMatcher *regexp.Regexp
	reg := regexp.MustCompile(PathRegex)
	sub := reg.FindStringSubmatch(path)
	muxRoute := regexp.QuoteMeta(sub[1])
	globSub := sub[4]
	switch globSub {
	case "*":
		pathMatcher = regexp.MustCompile(fmt.Sprintf("^%s(/[^/]*)?$", muxRoute))
	case "**":
		pathMatcher = regexp.MustCompile(fmt.Sprintf("^%s(/.*)?$", muxRoute))
	default:
		pathMatcher = regexp.MustCompile(fmt.Sprintf("^%s$", muxRoute))
	}
	return pathMatcher
}

type HostMatchers []*HostMatcher

func (m HostMatchers) Match(s string) bool {
	for _, matcher := range m {
		if matcher.Match(s) {
			return true
		}
	}
	return false
}

type HostMatcher struct {
	glob.Glob
	raw string
}

func NewHostMatcher(hostOrWildcard string) *HostMatcher {
	return &HostMatcher{
		Glob: glob.MustCompile(hostOrWildcard, '.'),
		raw:  hostOrWildcard,
	}
}

func (re *HostMatcher) Load(s string) error {
	var err error
	re.Glob, err = glob.Compile(s, '.')
	re.raw = s
	return err
}

func (re *HostMatcher) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return fmt.Errorf("when unmarshal host matcher: %s", err.Error())
	}
	err = re.Load(s)
	if err != nil {
		return fmt.Errorf("when unmarshal host matcher: %s", err.Error())
	}
	return nil
}

func (re *HostMatcher) UnmarshalCloud(data interface{}) error {
	return re.Load(data.(string))
}

func (re *HostMatcher) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return fmt.Errorf("when unmarshal host matcher: %s", err.Error())
	}
	err = re.Load(s)
	if err != nil {
		return fmt.Errorf("when unmarshal host matcher: %s", err.Error())
	}
	return nil
}

func (re HostMatcher) String() string {
	return re.raw
}
