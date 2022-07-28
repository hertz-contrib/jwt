# Hertz-JWT(*This is a community driven project*)

This is a middleware for [Hertz](https://github.com/cloudwego/hertz) framework.

It uses [jwt-go](https://github.com/golang-jwt/jwt) to provide a jwt authentication middleware. It provides additional handler functions to provide the `login` api that will generate the token and an additional `refresh` handler that can be used to refresh tokens.

This repo is forked from [gin-jwt](https://github.com/appleboy/gin-jwt) and adapted to Hertz.

## Security Issue

Simple HS256 JWT token brute force cracker. Effective only to crack JWT tokens with weak secrets. **Recommendation**: Use strong long secrets or `RS256` tokens. See the [jwt-cracker repository](https://github.com/lmammino/jwt-cracker).

## Usage

Download and install:

```sh
export GO111MODULE=on
go get github.com/hertz-contrib/jwt
```

Import it in your code:

```go
import "github.com/hertz-contrib/jwt"
```

## Example

Please see [the example file](example/basic/main.go) and you can use `ExtractClaims` to fetch user data.


```go
package main

import (
   "context"
   "log"
   "time"

   "github.com/cloudwego/hertz/pkg/app"
   "github.com/cloudwego/hertz/pkg/app/server"
   "github.com/hertz-contrib/jwt"
)

type login struct {
   Username string `form:"username,required" json:"username,required"`
   Password string `form:"password,required" json:"password,required"`
}

var identityKey = "id"

func PingHandler(c context.Context, ctx *app.RequestContext) {
   ctx.JSON(200, map[string]string{
      "ping": "pong",
   })
}

// User demo
type User struct {
   UserName  string
   FirstName string
   LastName  string
}

func main() {
   h := server.Default()

   // the jwt middleware
   authMiddleware, err := jwt.New(&jwt.HertzJWTMiddleware{
      Realm:       "test zone",
      Key:         []byte("secret key"),
      Timeout:     time.Hour,
      MaxRefresh:  time.Hour,
      IdentityKey: identityKey,
      PayloadFunc: func(data interface{}) jwt.MapClaims {
         if v, ok := data.(*User); ok {
            return jwt.MapClaims{
               identityKey: v.UserName,
            }
         }
         return jwt.MapClaims{}
      },
      IdentityHandler: func(ctx context.Context, c *app.RequestContext) interface{} {
         claims := jwt.ExtractClaims(ctx, c)
         return &User{
            UserName: claims[identityKey].(string),
         }
      },
      Authenticator: func(ctx context.Context, c *app.RequestContext) (interface{}, error) {
         var loginVals login
         if err := c.BindAndValidate(&loginVals); err != nil {
            return "", jwt.ErrMissingLoginValues
         }
         userID := loginVals.Username
         password := loginVals.Password

         if (userID == "admin" && password == "admin") || (userID == "test" && password == "test") {
            return &User{
               UserName:  userID,
               LastName:  "Hertz",
               FirstName: "CloudWeGo",
            }, nil
         }

         return nil, jwt.ErrFailedAuthentication
      },
      Authorizator: func(data interface{}, ctx context.Context, c *app.RequestContext) bool {
         if v, ok := data.(*User); ok && v.UserName == "admin" {
            return true
         }

         return false
      },
      Unauthorized: func(ctx context.Context, c *app.RequestContext, code int, message string) {
         c.JSON(code, map[string]interface{}{
            "code":    code,
            "message": message,
         })
      },
      // TokenLookup is a string in the form of "<source>:<name>" that is used
      // to extract token from the request.
      // Optional. Default value "header:Authorization".
      // Possible values:
      // - "header:<name>"
      // - "query:<name>"
      // - "cookie:<name>"
      // - "param:<name>"
      TokenLookup: "header: Authorization, query: token, cookie: jwt",
      // TokenLookup: "query:token",
      // TokenLookup: "cookie:token",

      // TokenHeadName is a string in the header. Default value is "Bearer". If you want empty value, use WithoutDefaultTokenHeadName.
      TokenHeadName: "Bearer",

      // TimeFunc provides the current time. You can override it to use another time value. This is useful for testing or if your server uses a different time zone than your tokens.
      TimeFunc: time.Now,
   })
   if err != nil {
      log.Fatal("JWT Error:" + err.Error())
   }

   // When you use jwt.New(), the function is already automatically called for checking,
   // which means you don't need to call it again.
   errInit := authMiddleware.MiddlewareInit()

   if errInit != nil {
      log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
   }

   h.POST("/login", authMiddleware.LoginHandler)

   h.NoRoute(authMiddleware.MiddlewareFunc(), func(ctx context.Context, c *app.RequestContext) {
      claims := jwt.ExtractClaims(ctx, c)
      log.Printf("NoRoute claims: %#v\n", claims)
      c.JSON(404, map[string]string{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
   })

   auth := h.Group("/auth")
   // Refresh time can be longer than token timeout
   auth.GET("/refresh_token", authMiddleware.RefreshHandler)
   auth.Use(authMiddleware.MiddlewareFunc())
   {
      auth.GET("/ping", PingHandler)
   }

   h.Spin()
}

```

## Demo

Please run example/basic/main.go file and listen `8888` port.

```sh
go run example/basic/main.go
```

Download and install [httpie](https://github.com/jkbrzt/httpie) CLI HTTP client.

### Login API

```sh
http -v --json POST localhost:8888/login username=admin password=admin
```

Output

```shell
POST /login HTTP/1.1
Accept: application/json, */*;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 42
Content-Type: application/json
Host: localhost:8888
User-Agent: HTTPie/3.2.1

{
    "password": "admin",
    "username": "admin"
}


HTTP/1.1 200 OK
Content-Length: 212
Content-Type: application/json; charset=utf-8
Date: Sun, 05 Jun 2022 04:49:20 GMT
Server: hertz

{
    "code": 200,
    "expire": "2022-06-05T13:49:20+08:00",
    "token": "**"
}
```

### Refresh token API

```bash
http -v -f GET localhost:8888/auth/refresh_token "Authorization:Bearer xxxxxxxxx"  "Content-Type: application/json"
```

Output

```shell
GET /auth/refresh_token HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Authorization: Bearer **
Connection: keep-alive
Content-Type: application/json
Host: localhost:8888
User-Agent: HTTPie/3.2.1



HTTP/1.1 200 OK
Content-Length: 212
Content-Type: application/json; charset=utf-8
Date: Sun, 05 Jun 2022 04:50:40 GMT
Server: hertz

{
    "code": 200,
    "expire": "2022-06-05T13:50:41+08:00",
    "token": "**"
}

```

### Hello world

Please login as `admin` and password as `admin`

```bash
http -f GET localhost:8888/auth/ping "Authorization:Bearer xxxxxxxxx"  "Content-Type: application/json"
```

Response message `200 OK`:

```sh
HTTP/1.1 200 OK
Content-Length: 15
Content-Type: application/json; charset=utf-8
Date: Sun, 05 Jun 2022 04:53:59 GMT
Server: hertz

{
    "ping": "pong"
}

```

### Authorization

Please login as `test` and password as `test`

```bash
http -f GET localhost:8888/auth/ping "Authorization:Bearer xxxxxxxxx"  "Content-Type: application/json"
```

Response message `403 Forbidden`:

```sh
HTTP/1.1 403 Forbidden
Content-Length: 74
Content-Type: application/json; charset=utf-8
Date: Sun, 05 Jun 2022 04:57:06 GMT
Server: hertz
Www-Authenticate: JWT realm=test zone

{
    "code": 403,
    "message": "you don't have permission to access this resource"
}

```

### Cookie Token

Use these options for setting the JWT in a cookie. See the Mozilla [documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies) for more information on these options.

```go
  SendCookie:       true,
  SecureCookie:     false, //non HTTPS dev environments
  CookieHTTPOnly:   true,  // JS can't modify
  CookieDomain:     "localhost:8888",
  CookieName:       "token", // default jwt
  TokenLookup:      "cookie:token",
  CookieSameSite:   http.SameSiteDefaultMode, //SameSiteDefaultMode, SameSiteLaxMode, SameSiteStrictMode, SameSiteNoneMode
```

### Login request flow (using the LoginHandler)

1. PROVIDED: `LoginHandler`

This is a provided function to be called on any login endpoint, which will trigger the flow described below.

2. REQUIRED: `Authenticator`
   This function should verify the user credentials given the hertz context (i.e. password matches hashed password for a given user email, and any other authentication logic). Then the authenticator should return a struct or map that contains the user data that will be embedded in the jwt token. This might be something like an account id, role, is_verified, etc. After having successfully authenticated, the data returned from the authenticator is passed in as a parameter into the `PayloadFunc`, which is used to embed the user identifiers mentioned above into the jwt token. If an error is returned, the `Unauthorized` function is used (explained below).

3. OPTIONAL: `PayloadFunc`

This function is called after having successfully authenticated (logged in). It should take whatever was returned from `Authenticator` and convert it into `MapClaims` (i.e. map[string]interface{}). A typical use case of this function is for when `Authenticator` returns a struct which holds the user identifiers, and that struct needs to be converted into a map. `MapClaims` should include one element that is [`IdentityKey` (default is "identity"): some_user_identity]. The elements of `MapClaims` returned in `PayloadFunc` will be embedded within the jwt token (as token claims). When users pass in their token on subsequent requests, you can get these claims back by using `ExtractClaims`.

4. OPTIONAL: `LoginResponse`

After having successfully authenticated with `Authenticator`, created the jwt token using the identifiers from map returned from `PayloadFunc`, and set it as a cookie if `SendCookie` is enabled, this function is called. It is used to handle any post-login logic. This might look something like using the hertz context to return a JSON of the token back to the user.

### Subsequent requests on endpoints requiring jwt token (using MiddlewareFunc).

1. PROVIDED: `MiddlewareFunc`

This is hertz middleware that should be used within any endpoints that require the jwt token to be present. This middleware will parse the request headers for the token if it exists, and check that the jwt token is valid (not expired, correct signature). Then it will call `IdentityHandler` followed by `Authorizator`. If `Authorizator` passes and all of the previous token validity checks passed, the middleware will continue the request. If any of these checks fail, the `Unauthorized` function is used (explained below).

2. OPTIONAL: `IdentityHandler`

The default of this function is likely sufficient for your needs. The purpose of this function is to fetch the user identity from claims embedded within the jwt token, and pass this identity value to `Authorizator`. This function assumes [`IdentityKey`: some_user_identity] is one of the attributes embedded within the claims of the jwt token (determined by `PayloadFunc`).

3. OPTIONAL: `Authorizator`

Given the user identity value (`data` parameter) and the hertz context, this function should check if the user is authorized to be reaching this endpoint (on the endpoints where the `MiddlewareFunc` applies). This function should likely use `ExtractClaims` to check if the user has the sufficient permissions to reach this endpoint, as opposed to hitting the database on every request. This function should return true if the user is authorized to continue through with the request, or false if they are not authorized (where `Unauthorized` will be called).

### Logout Request flow (using LogoutHandler)

1. PROVIDED: `LogoutHandler`

This is a provided function to be called on any logout endpoint, which will clear any cookies if `SendCookie` is set, and then call `LogoutResponse`.

2. OPTIONAL: `LogoutResponse`

This should likely just return back to the user the http status code, if logout was successful or not.

### Refresh Request flow (using RefreshHandler)

1. PROVIDED: `RefreshHandler`:

This is a provided function to be called on any refresh token endpoint. If the token passed in is was issued within the `MaxRefreshTime` time frame, then this handler will create/set a new token similar to the `LoginHandler`, and pass this token into `RefreshResponse`

2. OPTIONAL: `RefreshResponse`:

This should likely return a JSON of the token back to the user, similar to `LoginResponse`

### Failures with logging in, bad tokens, or lacking privileges

1. OPTIONAL `Unauthorized`:

On any error logging in, authorizing the user, or when there was no token or a invalid token passed in with the request, the following will happen. The hertz context will be aborted depending on `DisabledAbort`, then `HTTPStatusMessageFunc` is called which by default converts the error into a string. Finally the `Unauthorized` function will be called. This function should likely return a JSON containing the http error code and error message to the user.
