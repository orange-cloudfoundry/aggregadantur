package models

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

func NewAuthWithOauth2(
	oauth2Auth *Oauth2Auth,
	oidcAuth *OIDCAuth,
	jwtChecks JWTChecks,
	includes, excludes PathMatchers,
) Auth {
	return Auth{
		Includes:   includes,
		Excludes:   excludes,
		Oauth2Auth: oauth2Auth,
		OIDCAuth:   oidcAuth,
		BasicAuth:  nil,
		JWTCheck:   jwtChecks,
	}
}

type Auth struct {
	// Includes Where to do Auth
	Includes PathMatchers `json:"includes" yaml:"includes" cloud:"includes"`
	// Excludes Where not to do Auth
	Excludes PathMatchers `json:"excludes" yaml:"excludes" cloud:"excludes"`
	// Oauth2 auth
	Oauth2Auth            *Oauth2Auth `json:"oauth2" yaml:"oauth2" cloud:"oauth2"`
	OIDCAuth              *OIDCAuth   `json:"oidc" yaml:"oidc" cloud:"oidc"`
	BasicAuth             *BasicAuth  `json:"basic_auth" yaml:"basic" cloud:"basic_auth"`
	JWTCheck              JWTChecks   `json:"jwt_checks" yaml:"jwt_checks" cloud:"jwt_checks"`
	LoginPageTemplate     string      `json:"login_page_template" yaml:"login_page_template" cloud:"login_page_template"`
	LoginPageTemplatePath string      `json:"login_page_template_path" yaml:"login_page_template_path" cloud:"login_page_template_path"`
}

type OIDCIdToken struct {
	Email         string `json:"email"`
	FamilyName    string `json:"family_name"`
	GivenName     string `json:"given_name"`
	PreferredName string `json:"preferred_username"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
	Sub           string `json:"sub"`
	Type          string `json:"typ"`
}

func (a Auth) MakeLoginPageTemplate(defaultTemplate string) (string, error) {
	if a.LoginPageTemplate != "" {
		return a.LoginPageTemplate, nil
	}
	if a.LoginPageTemplatePath == "" {
		return defaultTemplate, nil
	}
	b, err := os.ReadFile(a.LoginPageTemplatePath)
	if err != nil {
		return "", err
	}
	a.LoginPageTemplate = string(b)
	return a.LoginPageTemplate, nil
}

type Oauth2Auth struct {
	TokenURL     string   `json:"token_url" yaml:"token_url" cloud:"token_url"`
	ClientID     string   `json:"client_id" yaml:"client_id" cloud:"client_id"`
	ClientSecret string   `json:"client_secret" yaml:"client_secret" cloud:"client_secret"`
	ParamsAsJson bool     `json:"params_as_json" yaml:"params_as_json" cloud:"params_as_json"`
	TokenFormat  string   `json:"token_format" yaml:"token_format" cloud:"token_format"`
	Scopes       []string `json:"scopes" yaml:"scopes" cloud:"scopes"`
}
type OIDCAuth struct {
	ClientID     string   `json:"client_id" yaml:"client_id" cloud:"client_id"`
	ClientSecret string   `json:"client_secret" yaml:"client_secret" cloud:"client_secret"`
	Issuer       string   `json:"issuer" yaml:"issuer" cloud:"issuer"`
	Scopes       []string `json:"scopes" yaml:"scopes" cloud:"scopes"`
	RedirectURI  string   `json:"redirect_uri" yaml:"redirect_uri" cloud:"redirect_uri"`
	Endpoint     string   `json:"endpoint" yaml:"endpoint" cloud:"endpoint"`
	AuthPath     string   `json:"auth_path" yaml:"auth_path" cloud:"auth_path"`
	CallbackPath string   `json:"callback_path" yaml:"callback_path" cloud:"callback_path"`
}

func NewOauth2Auth(
	tokenURL string,
	clientID string,
	clientSecret string,
	scopes []string,
) *Oauth2Auth {
	return &Oauth2Auth{
		TokenURL:     tokenURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		ParamsAsJson: false,
		TokenFormat:  "jwt",
		Scopes:       scopes,
	}
}

func GenerateState() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(fmt.Errorf("failed to generate random state: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func GenerateCodeVerifier() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(fmt.Errorf("failed to generate code verifier: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func GenerateCodeChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (c *Oauth2Auth) Load() error {
	if c.TokenFormat == "" {
		c.TokenFormat = "jwt"
	}
	return nil
}

func (c *Oauth2Auth) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Oauth2Auth
	err := unmarshal((*plain)(c))
	if err != nil {
		return fmt.Errorf("when unmarshal oauth2: %s", err.Error())
	}
	err = c.Load()
	if err != nil {
		return fmt.Errorf("when unmarshal oauth2: %s", err.Error())
	}
	return nil
}

func (c *Oauth2Auth) UnmarshalJSON(b []byte) error {
	type plain Oauth2Auth
	err := json.Unmarshal(b, (*plain)(c))
	if err != nil {
		return fmt.Errorf("when unmarshal oauth2: %s", err.Error())
	}
	err = c.Load()
	if err != nil {
		return fmt.Errorf("when unmarshal oauth2: %s", err.Error())
	}
	return nil
}

type BasicAuth struct {
	Username string   `json:"username" yaml:"username" cloud:"username"`
	Password string   `json:"password" yaml:"password" cloud:"password"`
	Scopes   []string `json:"scope" yaml:"scope" cloud:"scope"`
}

func (a Auth) Match(path string) bool {
	if a.Excludes.Match(path) {
		return false
	}

	return a.Includes.Match(path)
}

type JWTChecks []JWTCheck

type JWTCheck struct {
	// Alg Algorithm to use to validate the token
	// This is mandatory due to a security issue (see: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries)
	Alg string `json:"alg" yaml:"alg" cloud:"alg"`
	// Secret or private key to verify the jwt
	// This is required
	Secret string `json:"secret" yaml:"secret" cloud:"secret"`
	// Issuer It will validate that the jwt contains this issuer
	Issuer string `json:"issuer" yaml:"issuer" cloud:"issuer"`
	// NotVerifyIssuedAt Set to true to not verify issued at of token (Useful when you have different time between user and server)
	NotVerifyIssuedAt bool `json:"not_verify_issued_at" yaml:"not_verify_expire" cloud:"not_verify_issued_at"`
}

func (es JWTChecks) FindJWTCheckByIssuer(issuer string) (JWTCheck, error) {
	for _, e := range es {
		if e.Issuer == issuer {
			return e, nil
		}
	}
	return JWTCheck{}, fmt.Errorf("jwt check with issuer %s not found", issuer)
}
