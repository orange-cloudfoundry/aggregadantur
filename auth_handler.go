package aggregadantur

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/sessions"
	"github.com/orange-cloudfoundry/aggregadantur/contexes"
	"github.com/orange-cloudfoundry/aggregadantur/jwtclaim"
	"github.com/orange-cloudfoundry/aggregadantur/models"
	"golang.org/x/oauth2"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type AuthHandler struct {
	next         http.Handler
	aggrRoute    *models.AggregateRoute
	httpClient   *http.Client
	store        sessions.Store
	oidcProvider *oidc.Provider
	oauth2Config *oauth2.Config
	oidcVerifier *oidc.IDTokenVerifier
}

func NewAuthHandler(next http.Handler, aggrRoute *models.AggregateRoute, httpClient *http.Client, store sessions.Store) *AuthHandler {
	handler := &AuthHandler{
		next:       next,
		aggrRoute:  aggrRoute,
		httpClient: httpClient,
		store:      store,
	}

	// Initialize OIDC provider if configured
	if aggrRoute.Auth.OIDCAuth != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
		provider, err := oidc.NewProvider(ctx, aggrRoute.Auth.OIDCAuth.Endpoint)
		if err != nil {
			panic(fmt.Errorf("failed to create OIDC provider: %w", err))
		}
		handler.oidcProvider = provider

		handler.oauth2Config = &oauth2.Config{
			ClientID:     aggrRoute.Auth.OIDCAuth.ClientID,
			ClientSecret: aggrRoute.Auth.OIDCAuth.ClientSecret,
			RedirectURL:  aggrRoute.Auth.OIDCAuth.RedirectURI,
			Endpoint:     provider.Endpoint(),
			Scopes:       aggrRoute.Auth.OIDCAuth.Scopes,
		}

		handler.oidcVerifier = provider.Verifier(&oidc.Config{
			ClientID: aggrRoute.Auth.OIDCAuth.ClientID,
		})

	}

	return handler

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
	if a.aggrRoute.Auth.OIDCAuth != nil && req.URL.Path == a.aggrRoute.Auth.OIDCAuth.AuthPath {
		a.redirectToOIDC(w, req)
		return
	}

	if a.aggrRoute.Auth.OIDCAuth != nil && req.URL.Path == a.aggrRoute.Auth.OIDCAuth.CallbackPath {
		a.handleOIDCCallback(w, req)
		return
	}

	_, _, hasBasicAuth := req.BasicAuth()
	if a.aggrRoute.Auth.BasicAuth != nil || hasBasicAuth {
		a.basicAuth(w, req)
		return
	}
	jwtToken := a.retrieveJwt(req)
	if jwtToken == "" {
		if a.aggrRoute.Auth.OIDCAuth != nil {
			a.oidcLoginPage(w, req)
			return
		} else {
			a.loginPage(w, req)
			return
		}
	}
	a.checkJwt(jwtToken, w, req)
}

func (a AuthHandler) redirectToOIDC(w http.ResponseWriter, req *http.Request) {
	session, err := a.getSession(req)
	if err != nil {
		log.Printf("Failed to get session: %v", err)
	}

	codeVerifier := models.GenerateCodeVerifier()
	codeChallenge := models.GenerateCodeChallenge(codeVerifier)
	session.Values["code_verifier"] = codeVerifier

	state := models.GenerateState()
	nonce := models.GenerateState()

	if state == "" || nonce == "" {
		http.Error(w, "Failed to generate security tokens", http.StatusInternalServerError)
		return
	}

	session.Values["state"] = state
	session.Values["nonce"] = nonce
	session.Values["state_created_at"] = time.Now().Unix()

	err = session.Save(req, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authUrl := a.oauth2Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", nonce),
	)

	http.Redirect(w, req, authUrl, http.StatusTemporaryRedirect)

}

func (a AuthHandler) handleOIDCCallback(w http.ResponseWriter, req *http.Request) {
	if errParam := req.URL.Query().Get("error"); errParam != "" {
		errDesc := req.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("OAuth error: %s - %s", errParam, errDesc), http.StatusBadRequest)
		return
	}

	session, err := a.getSession(req)
	if err != nil {
		log.Printf("Failed to get session: %v", err)
	}

	if createdAt, ok := session.Values["state_created_at"].(int64); ok {
		if time.Now().Unix()-createdAt > 180 {
			http.Error(w, "Authentication session expired", http.StatusBadRequest)
			return
		}
	}

	state := req.URL.Query().Get("state")
	savedState, ok := session.Values["state"].(string)

	validState, err := jwtclaim.VerifyState(state, savedState)
	if err != nil || !validState || !ok {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	code := req.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "code not found", http.StatusBadRequest)
		return
	}

	if usedCode, ok := session.Values["used_code"].(string); ok && usedCode == code {
		http.Error(w, "Authorization code already used", http.StatusBadRequest)
		return
	}

	session.Values["used_code"] = code
	err = session.Save(req, w)
	if err != nil {
		log.Printf("Failed to save session: %v", err)
	}

	codeVerifier, ok := session.Values["code_verifier"].(string)
	if !ok || codeVerifier == "" {
		http.Error(w, "Authentication session not found or expired", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	oauth2Token, err := a.oauth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to exchange code: %s", err.Error()), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	idToken, err := a.oidcVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if !oauth2Token.Expiry.IsZero() {
		session.Options.MaxAge = int(time.Until(oauth2Token.Expiry).Seconds())
	}

	validAudience := false
	validAudience = jwtclaim.VerifyAud(idToken.Audience, a.aggrRoute.Auth.OIDCAuth.ClientID, true)

	if !validAudience {
		http.Error(w, "Invalid audience in ID token", http.StatusBadRequest)
		return
	}

	validIssuer := jwtclaim.VerifyIss(idToken.Issuer, a.aggrRoute.Auth.OIDCAuth.Issuer, false)
	if !validIssuer {
		http.Error(w, "Invalid issuer in ID token", http.StatusBadRequest)
		return
	}

	nonce, ok := session.Values["nonce"].(string)
	validNonce, err := jwtclaim.VerifyNonce(idToken.Nonce, nonce)
	if err != nil || !validNonce || !ok {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauth2Token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var userInfo models.OIDCIdToken
	err = json.Unmarshal(*resp.IDTokenClaims, &userInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if userInfo.Sub == "" {
		http.Error(w, "Missing subject claim", http.StatusBadRequest)
		return
	}
	if userInfo.Email == "" {
		http.Error(w, "Email not found or not verified", http.StatusBadRequest)
		return
	}

	delete(session.Values, "used_code")
	delete(session.Values, "code_verifier")
	delete(session.Values, "state")
	delete(session.Values, "nonce")
	delete(session.Values, "state_created_at")

	// Get original redirect URL
	redirectUrl := "/"
	if r, ok := session.Values["redirect_after_login"]; ok {
		redirectUrl = r.(string)
		delete(session.Values, "redirect_after_login")
	}

	session.Options.MaxAge = -1
	err = session.Save(req, w)
	if err != nil {
		log.Printf("Failed to invalidate old session: %v", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth-" + a.aggrRoute.Name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	newSession, err := a.getSession(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newSession.Values["jwt_token"] = oauth2Token.AccessToken

	if !oauth2Token.Expiry.IsZero() {
		newSession.Options.MaxAge = int(time.Until(oauth2Token.Expiry).Seconds())
	}
	err = session.Save(req, w)
	if err != nil {
		log.Printf("Failed to save session: %v", err)
	}

	http.Redirect(w, req, redirectUrl, http.StatusFound)
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
	var scopes []string
	if a.aggrRoute.Auth.OIDCAuth != nil {
		scopes = a.aggrRoute.Auth.OIDCAuth.Scopes
	} else {
		scopes = a.aggrRoute.Auth.Oauth2Auth.Scopes
	}
	for _, scopeByPriorities := range scopes {
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
	session, err := a.getSession(req)
	if err != nil {
		//log the error and continue to check Authorization header
		log.Printf("Failed to get session: %v", err)
	}

	if j, ok := session.Values["jwt_token"]; ok {
		return j.(string)
	}
	authorization := req.Header.Get("Authorization")
	authSplit := strings.SplitN(authorization, " ", 2)
	if len(authSplit) >= 2 && strings.EqualFold(authSplit[0], "bearer") {
		return authSplit[1]
	}
	return ""
}

func (a AuthHandler) oidcLoginPage(w http.ResponseWriter, req *http.Request) {
	session, err := a.getSession(req)
	if err != nil {
		log.Printf("Failed to get session: %v", err)
	}

	redirectUrl := req.URL.Path
	if req.URL.RawQuery != "" {
		redirectUrl += "?" + req.URL.RawQuery
	}
	redirectUrl = a.sanitizeRedirectUrl(redirectUrl)

	session.Values["redirect_after_login"] = redirectUrl
	err = session.Save(req, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if req.Method == http.MethodPost {
		http.Redirect(w, req, a.aggrRoute.Auth.OIDCAuth.AuthPath, http.StatusFound)
		return
	}

	loginPageTemplate, err := a.aggrRoute.Auth.MakeLoginPageTemplate(DefaultOIDCLoginTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	_, err = w.Write([]byte(makeLoginPageHtml(
		loginPageTemplate,
		cases.Title(language.AmericanEnglish).String(a.aggrRoute.Name),
		redirectUrl,
	)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a AuthHandler) loginPage(w http.ResponseWriter, req *http.Request) {
	redirectUrl := req.URL.Path
	if req.URL.RawQuery != "" {
		redirectUrl += "?" + req.URL.RawQuery
	}
	redirectUrl = a.sanitizeRedirectUrl(redirectUrl)
	loginPageTemplate, err := a.aggrRoute.Auth.MakeLoginPageTemplate(DefaultLoginTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if req.Method == http.MethodGet {

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")

		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte(makeLoginPageHtml(
			loginPageTemplate,
			cases.Title(language.AmericanEnglish).String(a.aggrRoute.Name),
			redirectUrl,
		)))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
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
		_, err := w.Write(fmt.Appendf(nil,
			`<html><head><meta http-equiv="refresh" content="3;url=%s" /></head><body><h1>You are not authorized: %s.</h1></body></html>`,
			html.EscapeString(req.URL.Path), html.EscapeString(err.Error())))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	session, err := a.getSession(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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

func (a AuthHandler) getSession(req *http.Request) (*sessions.Session, error) {
	session, err := a.store.Get(req, "auth-"+a.aggrRoute.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	return session, nil
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
		b, _ := io.ReadAll(resp.Body)
		return AccessTokenResponse{}, fmt.Errorf("from oauth server %d: %s", resp.StatusCode, string(b))
	}
	b, err := io.ReadAll(resp.Body)
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

	return AccessTokenResponse{}, fmt.Errorf("you have no valid scopes")
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
		return nil, fmt.Errorf("token doesn't contains the requested issuer")
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

func (a AuthHandler) sanitizeRedirectUrl(redirectUrl string) string {
	redirectUrl = strings.TrimSpace(redirectUrl)

	if redirectUrl == "" {
		return "/"
	}

	parsed, err := url.Parse(redirectUrl)
	if err != nil {
		return "/"
	}
	if parsed.Scheme != "" || parsed.Host != "" {
		return "/"
	}

	lower := strings.ToLower(parsed.Path)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "vbscript:") {
		return "/"
	}

	if !strings.HasPrefix(parsed.Path, "/") {
		parsed.Path = "/" + parsed.Path
	}

	parsed.Path = path.Clean(parsed.Path)

	return parsed.RequestURI()
}
