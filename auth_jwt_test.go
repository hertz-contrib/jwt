// The MIT License (MIT)
//
// Copyright (c) 2016 Bo-Yi Wu
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// This file may have been modified by CloudWeGo authors. All CloudWeGo
// Modifications are Copyright 2022 CloudWeGo Authors.

package jwt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tidwall/gjson"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/route"
	"github.com/golang-jwt/jwt/v4"
)

// Login form structure.
type Login struct {
	Username string `json:"username,required"` //lint:ignore SA5008 ignoreCheck
	Password string `json:"password,required"` //lint:ignore SA5008 ignoreCheck
}

var (
	key                  = []byte("secret key")
	defaultAuthenticator = func(ctx context.Context, c *app.RequestContext) (interface{}, error) {
		var loginVals Login
		userID := loginVals.Username
		password := loginVals.Password

		if userID == "admin" && password == "admin" {
			return userID, nil
		}

		return userID, ErrFailedAuthentication
	}
)

func makeTokenString(SigningAlgorithm, username string) string {
	if SigningAlgorithm == "" {
		SigningAlgorithm = "HS256"
	}

	token := jwt.New(jwt.GetSigningMethod(SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = username
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = time.Now().Unix()
	var tokenString string
	if SigningAlgorithm == "RS256" {
		keyData, _ := ioutil.ReadFile("testdata/jwtRS256.key")
		signKey, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)
		tokenString, _ = token.SignedString(signKey)
	} else {
		tokenString, _ = token.SignedString(key)
	}

	return tokenString
}

func makeTokenStringWithUserID(SigningAlgorithm string, userID int64) string {
	if SigningAlgorithm == "" {
		SigningAlgorithm = "HS256"
	}

	token := jwt.New(jwt.GetSigningMethod(SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = userID
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = time.Now().Unix()
	var tokenString string
	if SigningAlgorithm == "RS256" {
		keyData, _ := ioutil.ReadFile("testdata/jwtRS256.key")
		signKey, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)
		tokenString, _ = token.SignedString(signKey)
	} else {
		tokenString, _ = token.SignedString(key)
	}

	return tokenString
}

func keyFunc(token *jwt.Token) (interface{}, error) {
	cert, err := ioutil.ReadFile("testdata/jwtRS256.key.pub")
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPublicKeyFromPEM(cert)
}

func TestMissingKey(t *testing.T) {
	_, err := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})

	assert.NotNil(t, err)
	assert.DeepEqual(t, ErrMissingSecretKey, err)
}

func TestMissingPrivKey(t *testing.T) {
	_, err := New(&HertzJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "nonexisting",
	})

	assert.NotNil(t, err)
	assert.DeepEqual(t, ErrNoPrivKeyFile, err)
}

func TestMissingPubKey(t *testing.T) {
	_, err := New(&HertzJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyFile:       "nonexisting",
	})

	assert.NotNil(t, err)
	assert.DeepEqual(t, ErrNoPubKeyFile, err)
}

func TestInvalidPrivKey(t *testing.T) {
	_, err := New(&HertzJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/invalidprivkey.key",
		PubKeyFile:       "testdata/jwtRS256.key.pub",
	})

	assert.NotNil(t, err)
	assert.DeepEqual(t, ErrInvalidPrivKey, err)
}

func TestInvalidPrivKeyBytes(t *testing.T) {
	_, err := New(&HertzJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyBytes:     []byte("Invalid_Private_Key"),
		PubKeyFile:       "testdata/jwtRS256.key.pub",
	})

	assert.NotNil(t, err)
	assert.DeepEqual(t, ErrInvalidPrivKey, err)
}

func TestInvalidPubKey(t *testing.T) {
	_, err := New(&HertzJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyFile:       "testdata/invalidpubkey.key",
	})

	assert.NotNil(t, err)
	assert.DeepEqual(t, ErrInvalidPubKey, err)
}

func TestInvalidPubKeyBytes(t *testing.T) {
	_, err := New(&HertzJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyBytes:      []byte("Invalid_Private_Key"),
	})

	assert.NotNil(t, err)
	assert.DeepEqual(t, ErrInvalidPubKey, err)
}

func TestMissingTimeOut(t *testing.T) {
	authMiddleware, err := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Authenticator: defaultAuthenticator,
	})

	assert.NotNil(t, err)
	assert.DeepEqual(t, time.Hour, authMiddleware.Timeout)
}

func TestMissingTokenLookup(t *testing.T) {
	authMiddleware, err := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Authenticator: defaultAuthenticator,
	})

	assert.NotNil(t, err)
	assert.DeepEqual(t, "header:Authorization", authMiddleware.TokenLookup)
}

func helloHandler(ctx context.Context, c *app.RequestContext) {
	c.JSON(200, map[string]interface{}{
		"text":  "Hello World.",
		"token": GetToken(ctx, c),
	})
}

func hertzHandler(auth *HertzJWTMiddleware) *route.Engine {
	r := route.NewEngine(config.NewOptions([]config.Option{}))

	r.POST("/login", auth.LoginHandler)
	r.POST("/logout", auth.LogoutHandler)
	// test token in path
	r.GET("/g/:token/refresh_token", auth.RefreshHandler)

	group := r.Group("/auth")
	// Refresh time can be longer than token timeout
	group.GET("/refresh_token", auth.RefreshHandler)
	group.Use(auth.MiddlewareFunc())
	{
		group.GET("/hello", helloHandler)
		group.POST("/hello", helloHandler)
	}

	return r
}

func TestMissingAuthenticatorForLoginHandler(t *testing.T) {
	authMiddleware, err := New(&HertzJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
	})

	assert.Nil(t, err)

	handler := hertzHandler(authMiddleware)

	body := bytes.NewReader([]byte("{\"username\": \"admin\",\"password\": \"admin\"}"))
	w := ut.PerformRequest(handler, http.MethodPost, "/login", &ut.Body{Body: body, Len: -1}, ut.Header{Key: "Content-Type", Value: "application/json"})
	resp := w.Result()
	assert.DeepEqual(t, ErrMissingAuthenticatorFunc.Error(), gjson.Get(string(resp.BodyBytes()), "message").String())
	assert.DeepEqual(t, http.StatusInternalServerError, w.Code)
}

func TestLoginHandler(t *testing.T) {
	// the middleware to test
	cookieName := "jwt"
	cookieDomain := "example.com"
	authMiddleware, err := New(&HertzJWTMiddleware{
		Realm: "test zone",
		Key:   key,
		PayloadFunc: func(data interface{}) MapClaims {
			// Set custom claim, to be checked in Authorizator method
			return MapClaims{"testkey": "testval", "exp": 0}
		},
		Authenticator: func(ctx context.Context, c *app.RequestContext) (interface{}, error) {
			var loginVals Login
			if binderr := c.BindAndValidate(&loginVals); binderr != nil {
				return "", ErrMissingLoginValues
			}
			userID := loginVals.Username
			password := loginVals.Password
			if userID == "admin" && password == "admin" {
				return userID, nil
			}
			return "", ErrFailedAuthentication
		},
		Authorizator: func(user interface{}, ctx context.Context, c *app.RequestContext) bool {
			return true
		},
		LoginResponse: func(ctx context.Context, c *app.RequestContext, code int, token string, t time.Time) {
			cookie := string(c.Cookie("jwt"))

			c.JSON(http.StatusOK, map[string]interface{}{
				"code":    http.StatusOK,
				"token":   token,
				"expire":  t.Format(time.RFC3339),
				"message": "login successfully",
				"cookie":  cookie,
			})
		},
		SendCookie:   true,
		CookieName:   cookieName,
		CookieDomain: cookieDomain,
		TimeFunc:     func() time.Time { return time.Now().Add(time.Duration(5) * time.Minute) },
	})

	assert.Nil(t, err)

	handler := hertzHandler(authMiddleware)

	body := bytes.NewReader([]byte("{\"username\": \"admin\"}"))
	w := ut.PerformRequest(handler, http.MethodPost, "/login", &ut.Body{Body: body, Len: -1}, ut.Header{Key: "Content-Type", Value: "application/json"})
	resp := w.Result()
	assert.DeepEqual(t, ErrMissingLoginValues.Error(), gjson.Get(string(resp.BodyBytes()), "message").String())
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)
	assert.DeepEqual(t, "application/json; charset=utf-8", string(resp.Header.ContentType()))

	body = bytes.NewReader([]byte("{\"username\": \"admin\",\"password\": \"test\"}"))
	w = ut.PerformRequest(handler, http.MethodPost, "/login", &ut.Body{Body: body, Len: -1}, ut.Header{Key: "Content-Type", Value: "application/json"})
	resp = w.Result()
	assert.DeepEqual(t, ErrFailedAuthentication.Error(), gjson.Get(string(resp.BodyBytes()), "message").String())
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	body = bytes.NewReader([]byte("{\"username\": \"admin\",\"password\": \"admin\"}"))
	w = ut.PerformRequest(handler, http.MethodPost, "/login", &ut.Body{Body: body, Len: -1}, ut.Header{Key: "Content-Type", Value: "application/json"})
	resp = w.Result()
	assert.DeepEqual(t, "login successfully", gjson.Get(string(resp.BodyBytes()), "message").String())
	assert.DeepEqual(t, http.StatusOK, w.Code)
	assert.True(t, strings.HasPrefix(string(resp.Header.FullCookie()), "jwt="))
	assert.True(t, strings.HasSuffix(string(resp.Header.FullCookie()), "; max-age=3600; domain=example.com; path=/"))
}

func TestParseToken(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization"})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Test 1234"})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("HS384", "admin")})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("HS256", "admin")})
	assert.DeepEqual(t, http.StatusOK, w.Code)
}

func TestParseTokenWithFrom(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		TokenLookup:   "form:Authorization",
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodPost, "/auth/hello", &ut.Body{
		Body: bytes.NewBufferString("Authorization=" + makeTokenString("HS256", "admin")),
		Len:  -1,
	}, ut.Header{
		Key:   "Content-Type",
		Value: "application/x-www-form-urlencoded",
	})
	assert.DeepEqual(t, http.StatusOK, w.Code)
}

func TestParseTokenRS256(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyFile:       "testdata/jwtRS256.key.pub",
		Authenticator:    defaultAuthenticator,
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization"})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Test 1234"})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("HS384", "admin")})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("RS256", "admin")})
	assert.DeepEqual(t, http.StatusOK, w.Code)
}

func TestParseTokenKeyFunc(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		KeyFunc:       keyFunc,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		// make sure it skips these settings
		Key:              []byte(""),
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "",
		PubKeyFile:       "",
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization"})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Test 1234"})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("HS384", "admin")})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("RS256", "admin")})
	assert.DeepEqual(t, http.StatusOK, w.Code)
}

func TestRefreshHandlerRS256(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyFile:       "testdata/jwtRS256.key.pub",
		SendCookie:       true,
		CookieName:       "jwt",
		Authenticator:    defaultAuthenticator,
		RefreshResponse: func(ctx context.Context, c *app.RequestContext, code int, token string, t time.Time) {
			cookie := string(c.Cookie("jwt"))

			c.JSON(http.StatusOK, map[string]interface{}{
				"code":    http.StatusOK,
				"token":   token,
				"expire":  t.Format(time.RFC3339),
				"message": "refresh successfully",
				"cookie":  cookie,
			})
		},
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token", nil, ut.Header{Key: "Authorization"})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token", nil, ut.Header{Key: "Authorization", Value: "Test 1234"})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token", nil,
		ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("RS256", "admin")},
		ut.Header{Key: "Cookie", Value: "jwt=" + makeTokenString("RS256", "admin")})
	resp := w.Result()
	assert.DeepEqual(t, "refresh successfully", gjson.Get(string(resp.BodyBytes()), "message").String())
	assert.DeepEqual(t, http.StatusOK, w.Code)
	assert.DeepEqual(t, makeTokenString("RS256", "admin"), gjson.Get(string(resp.BodyBytes()), "cookie").String())
}

func TestRefreshHandler(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token", nil, ut.Header{Key: "Authorization"})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token", nil, ut.Header{Key: "Authorization", Value: "Test 1234"})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("HS256", "admin")})
	assert.DeepEqual(t, http.StatusOK, w.Code)
}

func TestExpiredTokenWithinMaxRefreshOnRefreshHandler(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    2 * time.Hour,
		Authenticator: defaultAuthenticator,
	})

	handler := hertzHandler(authMiddleware)

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = "admin"
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	claims["orig_iat"] = time.Now().Add(-time.Hour).Unix()
	tokenString, _ := token.SignedString(key)

	// We should be able to refresh a token that has expired but is within the MaxRefresh time
	w := ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token", nil, ut.Header{Key: "Authorization", Value: "Bearer " + tokenString})
	assert.DeepEqual(t, http.StatusOK, w.Code)
}

func TestExpiredTokenOnRefreshHandler(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
	})

	handler := hertzHandler(authMiddleware)

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = "admin"
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = 0
	tokenString, _ := token.SignedString(key)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token", nil, ut.Header{Key: "Authorization", Value: "Bearer " + tokenString})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)
}

func TestAuthorizator(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		Authorizator: func(data interface{}, ctx context.Context, c *app.RequestContext) bool {
			return data.(string) == "admin"
		},
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("HS256", "test")})
	assert.DeepEqual(t, http.StatusForbidden, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("HS256", "admin")})
	assert.DeepEqual(t, http.StatusOK, w.Code)
}

func TestParseTokenWithJsonNumber(t *testing.T) {
	var userID int64 = 64
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		IdentityHandler: func(ctx context.Context, c *app.RequestContext) interface{} {
			claims := ExtractClaims(ctx, c)
			testNum, err := claims["identity"].(json.Number).Int64()
			assert.Nil(t, err)
			assert.DeepEqual(t, userID, testNum)
			return testNum
		},
		Unauthorized: func(ctx context.Context, c *app.RequestContext, code int, message string) {
			c.String(code, message)
		},
		ParseOptions: []jwt.ParserOption{jwt.WithJSONNumber()},
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenStringWithUserID("HS256", userID)})
	assert.DeepEqual(t, http.StatusOK, w.Code)
}

func TestClaimsDuringAuthorization(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		PayloadFunc: func(data interface{}) MapClaims {
			if v, ok := data.(MapClaims); ok {
				return v
			}

			if reflect.TypeOf(data).String() != "string" {
				return MapClaims{}
			}

			var testkey string
			switch data.(string) {
			case "admin":
				testkey = "1234"
			case "test":
				testkey = "5678"
			case "Guest":
				testkey = ""
			}
			// Set custom claim, to be checked in Authorizator method
			return MapClaims{"identity": data.(string), "testkey": testkey, "exp": 0}
		},
		Authenticator: func(ctx context.Context, c *app.RequestContext) (interface{}, error) {
			var loginVals Login

			if err := c.BindAndValidate(&loginVals); err != nil {
				return "", ErrMissingLoginValues
			}

			userID := loginVals.Username
			password := loginVals.Password

			if userID == "admin" && password == "admin" {
				return userID, nil
			}

			if userID == "test" && password == "test" {
				return userID, nil
			}

			return "Guest", ErrFailedAuthentication
		},
		Authorizator: func(user interface{}, ctx context.Context, c *app.RequestContext) bool {
			jwtClaims := ExtractClaims(ctx, c)

			if jwtClaims["identity"] == "administrator" {
				return true
			}

			if jwtClaims["testkey"] == "1234" && jwtClaims["identity"] == "admin" {
				return true
			}

			if jwtClaims["testkey"] == "5678" && jwtClaims["identity"] == "test" {
				return true
			}

			return false
		},
	})

	handler := hertzHandler(authMiddleware)

	userToken, _, _ := authMiddleware.TokenGenerator(MapClaims{
		"identity": "administrator",
	})

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + userToken})
	assert.DeepEqual(t, http.StatusOK, w.Code)

	body := bytes.NewReader([]byte("{\"username\": \"admin\",\"password\": \"admin\"}"))
	w = ut.PerformRequest(handler, http.MethodPost, "/login", &ut.Body{Body: body, Len: -1}, ut.Header{Key: "Content-Type", Value: "application/json"})
	resp := w.Result()
	assert.DeepEqual(t, http.StatusOK, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + gjson.Get(string(resp.BodyBytes()), "token").String()})
	assert.DeepEqual(t, http.StatusOK, w.Code)

	body = bytes.NewReader([]byte("{\"username\": \"test\",\"password\": \"test\"}"))
	w = ut.PerformRequest(handler, http.MethodPost, "/login", &ut.Body{Body: body, Len: -1}, ut.Header{Key: "Content-Type", Value: "application/json"})
	resp = w.Result()
	assert.DeepEqual(t, http.StatusOK, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + gjson.Get(string(resp.BodyBytes()), "token").String()})
	assert.DeepEqual(t, http.StatusOK, w.Code)
}

func ConvertClaims(claims MapClaims) map[string]interface{} {
	return map[string]interface{}{}
}

func TestEmptyClaims(t *testing.T) {
	var jwtClaims MapClaims

	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(ctx context.Context, c *app.RequestContext) (interface{}, error) {
			var loginVals Login
			userID := loginVals.Username
			password := loginVals.Password

			if userID == "admin" && password == "admin" {
				return "", nil
			}

			if userID == "test" && password == "test" {
				return "Administrator", nil
			}

			return userID, ErrFailedAuthentication
		},
		Unauthorized: func(ctx context.Context, c *app.RequestContext, code int, message string) {
			assert.True(t, len(ExtractClaims(ctx, c)) == 0)
			assert.True(t, len(ConvertClaims(ExtractClaims(ctx, c))) == 0)
			c.String(code, message)
		},
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer 1234"})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	assert.True(t, len(jwtClaims) == 0)
}

func TestUnauthorized(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(ctx context.Context, c *app.RequestContext, code int, message string) {
			c.String(code, message)
		},
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer 1234"})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)
}

func TestTokenExpire(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    -time.Second,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(ctx context.Context, c *app.RequestContext, code int, message string) {
			c.String(code, message)
		},
	})

	handler := hertzHandler(authMiddleware)

	userToken, _, _ := authMiddleware.TokenGenerator(MapClaims{
		"identity": "admin",
	})

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token", nil, ut.Header{Key: "Authorization", Value: "Bearer " + userToken})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)
}

func TestTokenFromQueryString(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(ctx context.Context, c *app.RequestContext, code int, message string) {
			c.String(code, message)
		},
		TokenLookup: "query:token",
	})

	handler := hertzHandler(authMiddleware)

	userToken, _, _ := authMiddleware.TokenGenerator(MapClaims{
		"identity": "admin",
	})

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token", nil, ut.Header{Key: "Authorization", Value: "Bearer " + userToken})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token?token="+userToken, nil, ut.Header{Key: "Authorization", Value: "Bearer " + userToken})
	assert.DeepEqual(t, http.StatusOK, w.Code)
}

func TestTokenFromParamPath(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(ctx context.Context, c *app.RequestContext, code int, message string) {
			c.String(code, message)
		},
		TokenLookup: "param:token",
	})

	handler := hertzHandler(authMiddleware)

	userToken, _, _ := authMiddleware.TokenGenerator(MapClaims{
		"identity": "admin",
	})

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token", nil, ut.Header{Key: "Authorization", Value: "Bearer " + userToken})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/g/"+userToken+"/refresh_token", nil)
	assert.DeepEqual(t, http.StatusOK, w.Code)
}

func TestTokenFromCookieString(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(ctx context.Context, c *app.RequestContext, code int, message string) {
			c.String(code, message)
		},
		TokenLookup: "cookie:token",
	})

	handler := hertzHandler(authMiddleware)

	userToken, _, _ := authMiddleware.TokenGenerator(MapClaims{
		"identity": "admin",
	})

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token", nil, ut.Header{Key: "Authorization", Value: "Bearer " + userToken})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + userToken})
	resp := w.Result()
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)
	assert.DeepEqual(t, "", gjson.Get(string(resp.BodyBytes()), "token").String())

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token", nil, ut.Header{Key: "Cookie", Value: "token=" + userToken})
	assert.DeepEqual(t, http.StatusOK, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Cookie", Value: "token=" + userToken})
	resp = w.Result()
	assert.DeepEqual(t, http.StatusOK, w.Code)
	assert.DeepEqual(t, userToken, gjson.Get(string(resp.BodyBytes()), "token").String())
}

func TestDefineTokenHeadName(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		TokenHeadName: "JWTTOKEN       ",
		Authenticator: defaultAuthenticator,
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("HS256", "admin")})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "JWTTOKEN " + makeTokenString("HS256", "admin")})
	assert.DeepEqual(t, http.StatusOK, w.Code)
}

func TestEmptyTokenHeadName(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:                       "test zone",
		Key:                         key,
		Timeout:                     time.Hour,
		TokenHeadName:               "",
		WithoutDefaultTokenHeadName: true,
		Authenticator:               defaultAuthenticator,
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("HS256", "admin")})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: makeTokenString("HS256", "admin")})
	assert.DeepEqual(t, http.StatusOK, w.Code)

	authMiddleware2, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		TokenHeadName: "",
		Authenticator: defaultAuthenticator,
	})

	handler = hertzHandler(authMiddleware2)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("HS256", "admin")})
	assert.DeepEqual(t, http.StatusOK, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: makeTokenString("HS256", "admin")})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)
}

func TestHTTPStatusMessageFunc(t *testing.T) {
	successError := errors.New("Successful test error")
	failedError := errors.New("Failed test error")
	successMessage := "Overwrite error message."

	authMiddleware, _ := New(&HertzJWTMiddleware{
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,

		HTTPStatusMessageFunc: func(e error, ctx context.Context, c *app.RequestContext) string {
			if e == successError {
				return successMessage
			}

			return e.Error()
		},
	})

	successString := authMiddleware.HTTPStatusMessageFunc(successError, nil, nil)
	failedString := authMiddleware.HTTPStatusMessageFunc(failedError, nil, nil)

	assert.DeepEqual(t, successMessage, successString)
	assert.NotEqual(t, successMessage, failedString)
}

func TestSendAuthorizationBool(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:             "test zone",
		Key:               key,
		Timeout:           time.Hour,
		MaxRefresh:        time.Hour * 24,
		Authenticator:     defaultAuthenticator,
		SendAuthorization: true,
		Authorizator: func(data interface{}, ctx context.Context, c *app.RequestContext) bool {
			return data.(string) == "admin"
		},
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("HS256", "test")})
	assert.DeepEqual(t, http.StatusForbidden, w.Code)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("HS256", "admin")})
	resp := w.Result()
	token := resp.Header.Get("Authorization")
	assert.DeepEqual(t, "Bearer "+makeTokenString("HS256", "admin"), token)
	assert.DeepEqual(t, http.StatusOK, w.Code)
}

func TestExpiredTokenOnAuth(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:             "test zone",
		Key:               key,
		Timeout:           time.Hour,
		MaxRefresh:        time.Hour * 24,
		Authenticator:     defaultAuthenticator,
		SendAuthorization: true,
		Authorizator: func(data interface{}, ctx context.Context, c *app.RequestContext) bool {
			return data.(string) == "admin"
		},
		TimeFunc: func() time.Time {
			return time.Now().AddDate(0, 0, 1)
		},
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + makeTokenString("HS256", "admin")})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)
}

func TestBadTokenOnRefreshHandler(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/refresh_token", nil, ut.Header{Key: "Authorization", Value: "Bearer " + "BadToken"})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)
}

func TestExpiredField(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
	})

	handler := hertzHandler(authMiddleware)

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = "admin"
	claims["orig_iat"] = 0
	tokenString, _ := token.SignedString(key)

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + tokenString})
	resp := w.Result()
	assert.DeepEqual(t, http.StatusBadRequest, w.Code)
	assert.DeepEqual(t, ErrMissingExpField.Error(), gjson.Get(string(resp.BodyBytes()), "message").String())

	// wrong format
	claims["exp"] = "wrongFormatForExpiryIgnoredByJwtLibrary"
	tokenString, _ = token.SignedString(key)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + tokenString})
	resp = w.Result()
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)
	assert.DeepEqual(t, ErrExpiredToken.Error(), strings.ToLower(gjson.Get(string(resp.BodyBytes()), "message").String()))
}

func TestCheckTokenString(t *testing.T) {
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       1 * time.Second,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(ctx context.Context, c *app.RequestContext, code int, message string) {
			c.String(code, message)
		},
		PayloadFunc: func(data interface{}) MapClaims {
			if v, ok := data.(MapClaims); ok {
				return v
			}

			return nil
		},
	})

	handler := hertzHandler(authMiddleware)

	userToken, _, _ := authMiddleware.TokenGenerator(MapClaims{
		"identity": "admin",
	})

	w := ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + userToken})
	assert.DeepEqual(t, http.StatusOK, w.Code)

	token, err := authMiddleware.ParseTokenString(userToken)
	assert.Nil(t, err)
	claims := ExtractClaimsFromToken(token)
	assert.DeepEqual(t, "admin", claims["identity"])

	time.Sleep(2 * time.Second)

	w = ut.PerformRequest(handler, http.MethodGet, "/auth/hello", nil, ut.Header{Key: "Authorization", Value: "Bearer " + userToken})
	assert.DeepEqual(t, http.StatusUnauthorized, w.Code)

	_, err = authMiddleware.ParseTokenString(userToken)
	assert.NotNil(t, err)
	assert.DeepEqual(t, MapClaims{}, ExtractClaimsFromToken(nil))
}

func TestLogout(t *testing.T) {
	cookieName := "jwt"
	cookieDomain := "example.com"
	// the middleware to test
	authMiddleware, _ := New(&HertzJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		SendCookie:    true,
		CookieName:    cookieName,
		CookieDomain:  cookieDomain,
	})

	handler := hertzHandler(authMiddleware)

	w := ut.PerformRequest(handler, http.MethodPost, "/logout", nil)
	assert.DeepEqual(t, http.StatusOK, w.Code)
	assert.DeepEqual(t, fmt.Sprintf("%s=; domain=%s; path=/", cookieName, cookieDomain), w.Header().Get("Set-Cookie"))
}
