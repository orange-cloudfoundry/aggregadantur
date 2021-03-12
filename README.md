# Aggregadantur

Aggregadantur is a lib to handle aggregation and security over oauth2/basic auth (basic auth is recommended only for
testing) on multiple endpoints.

It has an embedded small server to be used as reverse proxy in front of a website.

## Install

### As a lib

The easiest way is to include in your configuration file a `*models.AggregateRoute` (
see [below for configuration in your file](#configuration-route)) and add your handler afterward and finally create the
router associate to this route, example:

```go
package main

import (
	"github.com/gorilla/sessions"
	"github.com/orange-cloudfoundry/aggregadantur"
	"github.com/orange-cloudfoundry/aggregadantur/models"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
)

type MyConfig struct {
	//...
	SessionKey     string                 `json:"session_key"`
	AggregateRoute *models.AggregateRoute `json:"aggregate_route"`
}

func main() {
	// load config file
	b, err := ioutil.ReadFile("./config.yml")
	if err != nil {
		panic(err)
	}

	var myConfig MyConfig
	// can be also json.Unmarshal or gautocloud.Inject
	err = yaml.Unmarshal(b, &myConfig)
	if err != nil {
		panic(err)
	}
	aggrRoute := myConfig.AggregateRoute

	// adding my own handler as upstream, aggregadantur will act as a middleware
	aggrRoute.Upstream = models.NewUpstreamFromHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("simple text\nmultiline"))
	}))

	// create a router, and add it a session store, here it is a cookie store, it is for saving session with token.
	sess := sessions.NewCookieStore([]byte(myConfig.SessionKey))
	rtr := aggregadantur.NewRouter(sess)
	// add you aggregate route
	err = rtr.AddMuxRoute(aggrRoute)
	if err != nil {
		panic(err)
	}
	// listen on it directly
	panic(http.ListenAndServe("127.0.0.1:8089", rtr))
}
```

### With small server

Create a config file named `config.yml` with this content (
see [below for configuration routes in your file](#configuration-aggregation-route)):

```yaml
server:
  # Where the server should listen
  # this can be empty if env var PORT set, it will be set as 0.0.0.0:${PORT}
  listen: 127.0.0.1:8000
  # Set a strong session_key, this will be used to encrypt cookie which contains oauth2 token
  session_key: "super-secure-session"
  # Set to true to enable ssl, you will need to fill tls_pem
  enable_ssl: false
  # Set pem files if you have enabled ssl
  tls_pem:
    cert_chain: ---pem format of cert chain
    private_key: --pem format of private key
logging:
  # set level of log (debug, info, warning, error, panic)
  level: info
  # Set to true to not have color
  no_color: false
  # Set to true to see logs in json
  in_json: true
routes: # routes see below
```

## Configuration Aggregation Route

```yaml
# Name of your aggregate route
name: my-route
# An identity to identify after in endpoints to aggregate
identifier: an-identity
# Includes path for making aggregation
# You can use globs:
#   - appending /* will only make requests available in first level to aggregate
#   - appending /** will mark everything to aggregate
# e.g.: /app/**
includes: [ "/**" ]
# The same as Includes except that's path matching this will be excluded of endpoint to be aggregated
excludes: [ "/metrics" ]
# Set to false to not let pass method Options on auth
options_passthrough: true
# Upstream URL where all request will be redirected
# Query parameters can be passed, e.g.: http:#localhost?param=1
# User and password are given as basic auth too (this is not recommended to use it), e.g.: http://user:password@localhost
# This can be empty if you will set an handler as upstream when using lib
upstream: http://localhost:8080
# By default response from upstream are buffered, it can be issue when sending big files
# Set to true to use stream response. retry will not be performed in this case
# Buffer is only use when upstream url exists
no_buffer: false
# Set to true to not check ssl certificates from upstream or endpoints (not really recommended)
insecure_skip_verify: false
# Must match host(s)
# You can set a wildcard on host like *.my-domain.com to only trigger reverse proxy on this domain
hosts: [ "*" ]
# Must match this beginning of path for let it pass in reverse proxy
# Note that this path will be remove before send path to upstream
# e.g. with prefix path `/foo`: `/foo/index` will give as `/index` to upstream
path: "/"
# Endpoints to aggregate in aggregate mode
# You MUST set always the current route as one of the endpoint to get value of the current one
# All requests to endpoints will be made in parallel before get aggregated
aggregate_endpoints:
  # declare itself
  - url: http://localhost:8000
    identifier: an-identity
  # declare a second endpoint
  - url: http://other-domain:8000
    identifier: an-identity2

# Set an auth which is independent of aggregation, you can set an auth on all path you want even if no aggregation exists
auth:
  # Includes path for triggering authentication
  # You can use globs:
  #   - appending /* will only make requests available in first level to aggregate
  #   - appending /** will mark everything to aggregate
  # e.g.: /app/**
  includes: [ "/**" ]
  # The same as Includes except that's path matching this will be excluded of authentication
  excludes: [ "/metrics" ]
  # Set oauth2 server, this server MUST implements grant type password (as uaa do)
  oauth2:
    # Token url to retrieve the token
    token_url: https://localhost:8080/oauth/token
    # Client id for making token request with grant type password
    client_id: "a client id"
    # Client secret for making token request with grant type password
    client_secret: "a client secret"
    # By default token retrieval is made in post form, you can either set to send params in json format
    params_as_json: false
    # Token format to retrieve when getting token (defaulting to `jwt`)
    token_format: "jwt"
    # Scopes that are allowed to enter
    scopes: [ "admin scope", "openid" ]
  # You can set basic auth but only for testing, this is not recommended
  basic_auth:
    - username: "admin"
      password: "admin"
      # set scopes to your user in addition of login information
      scopes: [ "admin scope", "openid" ]
  # You should be able to verify all jwt for each endpoints
  # this let you set all jwt checks you want
  jwt_checks:
    # You must set alg of the token
    # we do not allow to retrieve freely from token itself, there was too much security issue in libs for that
    - alg: RS256
      # Secret public key to verify signature
      secret: "secret public key"
      # Set the issuer which create the token (normally the same url as auth.oauth2.token_url
      issuer: https://localhost:8080/oauth/token
      # Set to true to not verify token expiration from current time
      # timezone can be an issue for verifying epire time, this is anyway check after that
      not_verify_expire: false
    - alg: RS256
      secret: "secret public key"
      issuer: https://other-domain:8080/oauth/token
      not_verify_expire: false
  # Set another login page template
  # you must use two %s, there is not golang templating just string format
  # First %s is route name and second %s is where to do post login
  # e.g.: `Login %s, %s` become `Login my-route, /`
  login_page_template: ""
  # If you prefer use a file instead of plain text
  login_page_template_path: "./my-login-page.html"
```

## How I do aggregation ?

For triggering aggregation you must pass either:

- The header `X-Aggregator-Mode: aggregate`
- The get parameter on url `aggregator_mode=aggregate`: `http://localhost?aggregator_mode=aggregate`

When aggregating you will get json in this format:

```json
{
  "an-identity": "json content or raw content",
  "an-identity2": "json content or raw content"
}
```

You can set exactly which endpoint to target with either:

- The header `X-Aggregator-Targets: an-identity,an-identity2,...`, it must contain the list of identifier
- The get parameter on url `aggregator_targets=an-identity,an-identity2,...`

## What I've received when on upstream

### When using handler

You can get username, scopes and tokens if auth has been triggered on this request:

```go
package main

import (
	"github.com/gorilla/sessions"
	"github.com/orange-cloudfoundry/aggregadantur"
	"github.com/orange-cloudfoundry/aggregadantur/contexes"
	"github.com/orange-cloudfoundry/aggregadantur/models"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
)

func main() {
	// ...

	// adding my own handler as upstream, aggregadantur will act as a middleware
	aggrRoute.Upstream = models.NewUpstreamFromHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		username := contexes.Username(req)
		scopes := contexes.Scopes(req)
		claim := contexes.JwtClaim(req)
		w.Write([]byte("simple text\nmultiline"))
	}))

	// ...
}
```

### When upstream

You receive headers:

- `Authorization` with jwt token
- `X-Aggregator-Username` with username when auth
- `X-Aggregator-Scopes` with scopes from user
