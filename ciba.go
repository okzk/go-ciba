package ciba

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	issuer          string
	bcAuthnEndpoint string
	tokenEndpoint   string
	scope           string
	clientID        string
	clientSecret    string
}

func NewClient(issuer, bcAuthnEndpoint, tokenEndpoint, scope, clientID, clientSecret string) *Client {
	return &Client{
		issuer:          issuer,
		bcAuthnEndpoint: bcAuthnEndpoint,
		tokenEndpoint:   tokenEndpoint,
		scope:           scope,
		clientID:        clientID,
		clientSecret:    clientSecret,
	}
}

type CIBAError struct {
	Status    int
	ErrorCode string
}

func (e *CIBAError) Error() string {
	return fmt.Sprintf("authntication failed. (status: %d, error: %s)", e.Status, e.ErrorCode)
}

var errorWebhookRedirect = errors.New("redirect not supported")

var httpClient = &http.Client{
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errorWebhookRedirect
	},
	Timeout: time.Second * 5,
}

func (c *Client) post(ctx context.Context, endpoint string, values url.Values, ret interface{}) (int, error) {
	requestBody := values.Encode()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(requestBody))
	if err != nil {
		return 0, err
	}
	req.ContentLength = int64(len(requestBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)

	res, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	return res.StatusCode, json.NewDecoder(res.Body).Decode(ret)
}

type AuthnResponse struct {
	AuthReqID string `json:"auth_req_id,omitempty"`
	ExpiresIn int    `json:"expires_in,omitempty"`
	Interval  int    `json:"interval,omitempty"`

	Error string `json:"error,omitempty"`
}

type Token struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`

	Error string `json:"error,omitempty"`

	claims jwt.MapClaims
}

func (t *Token) Claims() jwt.MapClaims {
	return t.claims
}

const leewayForClockSkew = 10

func (c *Client) parseIDToken(idToken string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	parser := &jwt.Parser{}
	if _, _, err := parser.ParseUnverified(idToken, claims); err != nil {
		return nil, err
	}

	if !claims.VerifyIssuer(c.issuer, false) {
		return nil, errors.New("invalid issuer")
	}
	if !claims.VerifyAudience(c.clientID, false) {
		return nil, errors.New("invalid audience")
	}
	now := time.Now().Unix()
	if !claims.VerifyExpiresAt(now-leewayForClockSkew, false) {
		return nil, errors.New("token expired")
	}
	if !claims.VerifyNotBefore(now+leewayForClockSkew, false) {
		return nil, errors.New("token is not valid")
	}

	return claims, nil
}

func validateAuthnRequestValues(values url.Values) error {
	n := len(values["login_hint"]) + len(values["login_hint_token"]) + len(values["id_token_hint"])
	if n == 0 {
		return errors.New("one of the hints is required")
	}
	if n != 1 {
		return errors.New("only one hint is allowed")
	}
	return nil
}

func (c *Client) Authenticate(ctx context.Context, params ...AuthenticationParam) (*Token, error) {
	values := url.Values{}
	for _, p := range params {
		p(values)
	}
	values.Set("scope", c.scope)
	if err := validateAuthnRequestValues(values); err != nil {
		return nil, err
	}

	authnRes := AuthnResponse{}
	status, err := c.post(ctx, c.bcAuthnEndpoint, values, &authnRes)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &CIBAError{Status: status, ErrorCode: authnRes.Error}
	}

	interval := 5 * time.Second
	if authnRes.Interval > 0 {
		interval = time.Second * time.Duration(authnRes.Interval)
	}
	if authnRes.ExpiresIn > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Second*time.Duration(authnRes.ExpiresIn))
		defer cancel()
	}

	timer := time.NewTimer(time.Hour * 24)
	defer timer.Stop()
	for {
		timer.Reset(interval)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			values := url.Values{}
			values.Set("auth_req_id", authnRes.AuthReqID)
			values.Set("grant_type", "urn:openid:params:grant-type:ciba")
			token := Token{}
			status, err := c.post(ctx, c.tokenEndpoint, values, &token)
			if err != nil {
				return nil, err
			}
			if status != http.StatusOK {
				if status == http.StatusBadRequest && token.Error == "authorization_pending" {
					continue
				}
				if status == http.StatusBadRequest && token.Error == "slow_down" {
					interval = interval * 5 / 4
					continue
				}
				return nil, &CIBAError{Status: status, ErrorCode: token.Error}
			}
			token.claims, err = c.parseIDToken(token.IDToken)
			if err != nil {
				return nil, err
			}
			return &token, nil
		}
	}
}
