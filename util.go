package osin

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"github.com/stretchr/objx"
)

// BasicAuth defines the values required for basic authentication.
type BasicAuth struct {
	Username string
	Password string
}

// CheckBasicAuth reads Basic authorization from the Authorization
// header.
func CheckBasicAuth(r *http.Request) (*BasicAuth, error) {
	if r.Header.Get("Authorization") == "" {
		return nil, nil
	}

	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Basic" {
		return nil, errors.New("Invalid authorization header")
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return nil, err
	}
	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return nil, errors.New("Invalid authorization message")
	}

	return &BasicAuth{Username: pair[0], Password: pair[1]}, nil
}

// Check client authentication in params if allowed, and on authorization header
func CheckClientAuth(r *http.Request, params objx.Map, useparams bool) (*BasicAuth, error) {
	if useparams {
		ret := &BasicAuth{
			Username: params.Get("client_id").Str(),
			Password: params.Get("client_secret").Str(),
		}
		if ret.Username != "" && ret.Password != "" {
			return ret, nil
		}
	}

	return CheckBasicAuth(r)
}

// GetValidAuth loads authorization using CheckClientAuth, then
// ensures that the authorization is valid.  It writes any error
// messages to the passed in *Response value and returns the error (so
// that you can stop processing if you don't need to go any further).
func GetValidAuth(request *http.Request, params objx.Map, allowSecretInParams bool, writer *Response) (*BasicAuth, error) {
	auth, err := CheckClientAuth(request, params, allowSecretInParams)
	if err != nil || auth == nil {
		writer.SetError(E_INVALID_REQUEST, "")
		if err == nil {
			err = errors.New("Client authentication not sent")
		}
		writer.InternalError = err
		return nil, err
	}
	return auth, nil
}

// GetValidClient takes a client id and a *Response, then
// tries to load a client from storage and validate that client.  It
// will return nil for the returned Client and an error if there are
// any problems locating or validating the requested client (i.e. if
// the client doesn't exist or has an empty GetRedirectUri()
// response), or the validated Client and nil for an error otherwise.
func (s *Server) GetValidClient(id string, writer *Response) (Client, error) {
	client, err := s.Storage.GetClient(id)
	if err != nil {
		writer.SetError(E_SERVER_ERROR, "")
		writer.InternalError = err
		return nil, err
	}
	if client == nil || client.GetRedirectUri() == "" {
		writer.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil, deferror.Get(E_UNAUTHORIZED_CLIENT)
	}
	return client, nil
}

// GetValidClientWithSecret takes a client id, secret, and a
// *Response, then returns the client if both GetValidClient returns a
// valid client and the passed in secret matches the client's secret.
func (s *Server) GetValidClientWithSecret(id, secret string, writer *Response) (Client, error) {
	client, err := s.GetValidClient(id, writer)
	if err != nil {
		return nil, err
	}
	if client.GetSecret() != secret {
		writer.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil, deferror.Get(E_UNAUTHORIZED_CLIENT)
	}
	return client, nil
}

// GetValidAuthData takes an authorization code and a *Response, then
// tries to load an AuthorizeData from storage and validate that data.
// It will return nil for the returned AuthorizeData and an error if
// there are any problems locating or validating the requested data
// (i.e. if the AuthorizeData's Client value returned from GetClient()
// is nil or has an empty GetRedirectUri() response), or the validated
// AuthorizeData and nil for an error otherwise.
func (s *Server) GetValidAuthData(code string, writer *Response) (AuthorizeData, error) {
	authData, err := s.Storage.LoadAuthorize(code)
	if err != nil {
		writer.SetError(E_INVALID_GRANT, "")
		writer.InternalError = err
		return nil, err
	}
	if authData.GetClient() == nil || authData.GetClient().GetRedirectUri() == "" {
		writer.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil, deferror.Get(E_UNAUTHORIZED_CLIENT)
	}
	if authData.IsExpired() {
		writer.SetError(E_INVALID_GRANT, "")
		return nil, deferror.Get(E_INVALID_GRANT)
	}
	return authData, nil
}

// GetValidAccessData takes a access token and a *Response, then
// tries to load an AccessData from storage and validate that data.
// It will return nil for the returned AccessData and an error if
// there are any problems locating or validating the requested data
// (i.e. if the AccessData's Client value returned from GetClient()
// is nil or has an empty GetRedirectUri() response), or the validated
// AccessData and nil for an error otherwise.
func (s *Server) GetValidAccessData(token string, writer *Response) (AccessData, error) {
	access, err := s.Storage.LoadAccess(token)
	if err != nil {
		writer.SetError(E_INVALID_REQUEST, "")
		writer.InternalError = err
		return nil, err
	}
	if access.GetClient() == nil {
		writer.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil, err
	}
	if access.IsExpired() {
		writer.SetError(E_INVALID_GRANT, "")
		return nil, err
	}
	return access, nil
}

// GetValidRefresh takes a refresh token and a *Response, then
// tries to load an AccessData from storage and validate that data.
// It will return nil for the returned AccessData and an error if
// there are any problems locating or validating the requested data
// (i.e. if the AccessData's Client value returned from GetClient()
// is nil or has an empty GetRedirectUri() response), or the validated
// AccessData and nil for an error otherwise.
func (s *Server) GetValidRefresh(token string, writer *Response) (AccessData, error) {
	access, err := s.Storage.LoadRefresh(token)
	if err != nil {
		writer.SetError(E_INVALID_GRANT, "")
		writer.InternalError = err
		return nil, err
	}
	if access.GetClient() == nil {
		writer.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil, deferror.Get(E_UNAUTHORIZED_CLIENT)
	}
	return access, nil
}
