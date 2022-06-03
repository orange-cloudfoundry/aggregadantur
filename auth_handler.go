package aggregadantur

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"github.com/form3tech-oss/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/orange-cloudfoundry/aggregadantur/contexes"
	"github.com/orange-cloudfoundry/aggregadantur/jwtclaim"
	"github.com/orange-cloudfoundry/aggregadantur/models"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type AuthHandler struct {
	next       http.Handler
	aggrRoute  *models.AggregateRoute
	httpClient *http.Client
	store      sessions.Store
}

func NewAuthHandler(next http.Handler, aggrRoute *models.AggregateRoute, httpClient *http.Client, store sessions.Store) *AuthHandler {
	return &AuthHandler{
		next:       next,
		aggrRoute:  aggrRoute,
		httpClient: httpClient,
		store:      store,
	}
}

func (a AuthHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if a.aggrRoute.OptionsPassthrough && req.Method == http.MethodOptions {
		a.next.ServeHTTP(w, req)
		return
	}
	if !a.aggrRoute.MatchAuth(req) {
		a.next.ServeHTTP(w, req)
		return
	}

	_, _, hasBasicAuth := req.BasicAuth()
	if a.aggrRoute.Auth.BasicAuth != nil || hasBasicAuth {
		a.basicAuth(w, req)
		return
	}
	jwtToken := a.retrieveJwt(req)
	if jwtToken == "" {
		a.loginPage(w, req)
		return
	}
	a.checkJwt(jwtToken, w, req)
}

func (a AuthHandler) checkJwt(jwtTokenRaw string, w http.ResponseWriter, req *http.Request) {
	parser := jwt.Parser{}
	parsedToken, _, err := parser.ParseUnverified(jwtTokenRaw, &jwtclaim.ScopeClaims{})
	if err != nil {
		panic(err)
	}
	claim := parsedToken.Claims.(*jwtclaim.ScopeClaims)
	jwtCheck, err := a.aggrRoute.Auth.JWTCheck.FindJWTCheckByIssuer(claim.Issuer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	signingMethod := jwt.GetSigningMethod(jwtCheck.Alg)
	if signingMethod == nil {
		http.Error(w, fmt.Sprintf("algorithm '%s' doesn't exists.", jwtCheck.Alg), http.StatusUnauthorized)
		return
	}

	whichScope := ""
	for _, scopeByPriorities := range a.aggrRoute.Auth.Oauth2Auth.Scopes {
		for _, scope := range claim.Scope {
			if scope == scopeByPriorities {
				whichScope = scope
				break
			}
		}
	}
	if whichScope == "" {
		http.Error(w, "you have no valid scopes.", http.StatusUnauthorized)
		return
	}

	_, err = jwt.Parse(jwtTokenRaw, func(token *jwt.Token) (interface{}, error) {
		return checkTokenfunc(token, jwtCheck, signingMethod)
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	req.Header.Set(XAggregatorScopesHeader, strings.Join(claim.Scope, ","))
	req.Header.Set(XAggregatorUsernameHeader, claim.Username)
	req.Header.Set("Authorization", "Bearer "+jwtTokenRaw)
	contexes.SetUsername(req, claim.Username)
	contexes.SetScopes(req, claim.Scope)
	contexes.SetJwtClaim(req, claim)
	a.next.ServeHTTP(w, req)
}

func (a AuthHandler) retrieveJwt(req *http.Request) string {
	session := a.getSession(req)
	if jwt, ok := session.Values["jwt_token"]; ok {
		return jwt.(string)
	}
	authorization := req.Header.Get("Authorization")
	authSplit := strings.SplitN(authorization, " ", 2)
	if len(authSplit) >= 2 && strings.EqualFold(authSplit[0], "bearer") {
		return authSplit[1]
	}
	return ""
}

func (a AuthHandler) loginPage(w http.ResponseWriter, req *http.Request) {
	redirectUrl := req.URL.Path
	if redirectUrl == "" {
		redirectUrl = "/"
	}
	if req.URL.RawQuery != "" {
		redirectUrl += "?" + req.URL.RawQuery
	}
	loginPageTemplate, err := a.aggrRoute.Auth.MakeLoginPageTemplate(DefaultLoginTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if req.Method == http.MethodGet {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(makeLoginPageHtml(
			loginPageTemplate,
			strings.Title(a.aggrRoute.Name),
			redirectUrl,
		)))
		return
	}
	err = req.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	authToken, err := a.oauth2Auth(req)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf(
			`<html><head><meta http-equiv="refresh" content="3;url=%s" /></head><body><h1>You are not authorized: %s.</h1></body></html>`,
			req.URL.Path, err.Error())))
		return
	}

	session := a.getSession(req)
	session.Values["jwt_token"] = authToken.AccessToken
	session.Options.MaxAge = authToken.ExpiresIn
	err = session.Save(req, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header.Del("Authorization")

	http.Redirect(w, req, redirectUrl, http.StatusTemporaryRedirect)
}

func (a AuthHandler) getSession(req *http.Request) *sessions.Session {
	session, _ := a.store.Get(req, "auth-"+a.aggrRoute.Name)
	return session
}

func (a AuthHandler) basicAuth(w http.ResponseWriter, req *http.Request) {
	user, password, hasBasicAuth := req.BasicAuth()
	if !hasBasicAuth || user == "" {
		http.Error(w, "no user provided", http.StatusUnauthorized)
		return
	}
	if a.aggrRoute.Auth.BasicAuth != nil {
		givenUser := sha256.Sum256([]byte(user))
		givenPass := sha256.Sum256([]byte(password))
		requiredUser := sha256.Sum256([]byte(a.aggrRoute.Auth.BasicAuth.Username))
		requiredPass := sha256.Sum256([]byte(a.aggrRoute.Auth.BasicAuth.Password))
		match := subtle.ConstantTimeCompare(givenUser[:], requiredUser[:]) == 1 &&
			subtle.ConstantTimeCompare(givenPass[:], requiredPass[:]) == 1
		if !match {
			http.Error(w, "Wrong user/password", http.StatusUnauthorized)
			return
		}
		req.Header.Set(XAggregatorScopesHeader, strings.Join(a.aggrRoute.Auth.BasicAuth.Scopes, ","))
		req.Header.Set(XAggregatorUsernameHeader, user)
		contexes.SetUsername(req, user)
		contexes.SetScopes(req, a.aggrRoute.Auth.BasicAuth.Scopes)
		a.next.ServeHTTP(w, req)
		return
	}
	accessResp, err := a.oauth2Auth(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	a.checkJwt(accessResp.AccessToken, w, req)
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

func (a AuthHandler) oauth2Auth(origReq *http.Request) (AccessTokenResponse, error) {

	var body io.Reader
	var contentType string
	authOption := a.aggrRoute.Auth.Oauth2Auth
	user := origReq.Form.Get("username")
	password := origReq.Form.Get("password")

	userBasicAuth, passwordBasicAuth, hasBasicAuth := origReq.BasicAuth()
	if user == "" && hasBasicAuth && userBasicAuth != "" {
		user = userBasicAuth
		password = passwordBasicAuth
	}

	if user == "" {
		return AccessTokenResponse{}, fmt.Errorf("no user provided")
	}

	if authOption.ParamsAsJson {
		body, contentType = a.generateJsonBody(user, password)
	} else {
		body, contentType = a.generateFormBody(user, password)
	}
	req, _ := http.NewRequest("POST", authOption.TokenURL, body)
	req.SetBasicAuth(authOption.ClientID, authOption.ClientSecret)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", contentType)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return AccessTokenResponse{}, fmt.Errorf("when getting token for %s: %s", user, err.Error())
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return AccessTokenResponse{}, fmt.Errorf("%d: Unauthorized on uaa", resp.StatusCode)
		}
		b, _ := ioutil.ReadAll(resp.Body)
		return AccessTokenResponse{}, fmt.Errorf("from oauth server %d: %s", resp.StatusCode, string(b))
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return AccessTokenResponse{}, fmt.Errorf("when getting token for %s: %s", user, err.Error())
	}
	var accessResp AccessTokenResponse
	err = json.Unmarshal(b, &accessResp)
	if err != nil {
		return AccessTokenResponse{}, fmt.Errorf("when getting token for %s: %s", user, err.Error())
	}

	scopes := strings.Split(accessResp.Scope, " ")
	for _, scopeByPriorities := range authOption.Scopes {
		for _, scope := range scopes {
			if scope == scopeByPriorities {
				origReq.Header.Set(XAggregatorScopesHeader, scopeByPriorities)
				return accessResp, nil
			}
		}
	}

	return AccessTokenResponse{}, fmt.Errorf("you have no valid scopes.")
}

func (a AuthHandler) generateFormBody(user, password string) (io.Reader, string) {
	formValues := make(url.Values)
	formValues.Add("grant_type", "password")
	formValues.Add("username", user)
	formValues.Add("password", password)
	tokenFormat := a.aggrRoute.Auth.Oauth2Auth.TokenFormat
	if tokenFormat != "" {
		formValues.Add("token_format", tokenFormat)
	}
	return strings.NewReader(formValues.Encode()), "application/x-www-form-urlencoded"
}

func (a AuthHandler) generateJsonBody(user, password string) (io.Reader, string) {
	params := struct {
		GrantType   string `json:"grant_type"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		TokenFormat string `json:"token_format,omitempty"`
	}{"password", user, password, a.aggrRoute.Auth.Oauth2Auth.TokenFormat}
	b, _ := json.Marshal(params)
	return bytes.NewReader(b), "application/json"
}

func checkTokenfunc(token *jwt.Token, jwtCheck models.JWTCheck, signingMethod jwt.SigningMethod) (interface{}, error) {
	mapClaims := token.Claims.(jwt.MapClaims)
	if jwtCheck.NotVerifyIssuedAt {
		mapClaims["iat"] = ""
	}
	err := mapClaims.Valid()
	if err != nil {
		return nil, err
	}

	if jwtCheck.Issuer != "" && !mapClaims.VerifyIssuer(jwtCheck.Issuer, true) {
		return nil, fmt.Errorf("Token doesn't contains the requested issuer.")
	}
	return getSecretEncoded(jwtCheck.Secret, signingMethod)
}

func getSecretEncoded(secret string, signingMethod jwt.SigningMethod) (interface{}, error) {
	bSecret := []byte(secret)
	if strings.HasPrefix(signingMethod.Alg(), "HS") {
		return bSecret, nil
	}
	if strings.HasPrefix(signingMethod.Alg(), "ES") {
		encSecret, err := jwt.ParseECPublicKeyFromPEM(bSecret)
		if err == nil {
			return encSecret, nil
		}
		return jwt.ParseECPrivateKeyFromPEM(bSecret)
	}
	// if no return token use RSA
	encSecret, err := jwt.ParseRSAPublicKeyFromPEM(bSecret)
	if err == nil {
		return encSecret, nil
	}
	return jwt.ParseRSAPrivateKeyFromPEM(bSecret)
}
