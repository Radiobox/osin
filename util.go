package osin

import (
	"encoding/base64"
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
func CheckBasicAuth(r *http.Request) (*BasicAuth, *HttpError) {
	if r.Header.Get("Authorization") == "" {
		return nil, nil
	}

	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Basic" {
		return nil, &HttpError{
			Status: http.StatusBadRequest,
			Message: "Invalid authorization header",
		}
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return nil, &HttpError{
			Status: http.StatusBadRequest,
			Message: "Could not decode basic auth: " + err.Error(),
		}
	}
	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return nil, &HttpError{
			Status: http.StatusBadRequest,
			Message: "Basic authorization must be a base64-encoded id:secret pair",
		}
	}

	return &BasicAuth{Username: pair[0], Password: pair[1]}, nil
}

// ChecClientAuth checks for client_id and client_secret in the
// Authorization header and (if useparams is true) request parameters.
func CheckClientAuth(r *http.Request, params objx.Map, useparams bool) (*BasicAuth, *HttpError) {
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
// ensures that the authorization is valid.  It returns a *HttpError
// if there are any problems with the request.
func GetValidAuth(request *http.Request, params objx.Map, allowSecretInParams bool) (*BasicAuth, *HttpError) {
	auth, err := CheckClientAuth(request, params, allowSecretInParams)
	if err != nil || auth == nil {
		if err == nil {
			err = &HttpError{
				Status: http.StatusUnauthorized,
				Message: "No client credentials received",
			}
		}
		return nil, err
	}
	return auth, nil
}

// GetValidClient takes a client id and a *Response, then
// tries to load a client from storage and validate that client.  It
// will return nil for the returned Client and a *HttpError if there
// are any problems locating or validating the requested client (i.e.
// if the client doesn't exist or has an empty GetRedirectUri()
// response), or the validated Client and nil for an error otherwise.
func (s *Server) GetValidClient(id string) (Client, *HttpError) {
	client, err := s.Storage.GetClient(id)
	if err != nil {
		if httpErr, ok := err.(*HttpError); ok {
			return nil, httpErr
		}
		return nil, &HttpError{
			Status: http.StatusInternalServerError,
			Message: err.Error(),
		}
	}
	if client == nil || client.GetRedirectUri() == "" {
		return nil, deferror.Get(E_UNAUTHORIZED_CLIENT)
	}
	return client, nil
}

// GetValidClientWithSecret takes a client id, secret, and a
// *Response, then returns the client if both GetValidClient returns a
// valid client and the passed in secret matches the client's secret.
func (s *Server) GetValidClientWithSecret(id, secret string) (Client, *HttpError) {
	client, err := s.GetValidClient(id, writer)
	if err != nil {
		return nil, err
	}
	if client.GetSecret() != secret {
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
func (s *Server) GetValidAuthData(code string) (AuthorizeData, *HttpError) {
	authData, err := s.Storage.LoadAuthorize(code)
	if err != nil {
		if httpErr, ok := err.(*HttpError); ok {
			return nil, httpErr
		}
		return nil, &HttpError{
			Status: http.StatusInternalServerError,
			Message: err.Error(),
		}
	}
	if authData.GetClient() == nil || authData.GetClient().GetRedirectUri() == "" {
		return nil, deferror.Get(E_UNAUTHORIZED_CLIENT)
	}
	if authData.IsExpired() {
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
func (s *Server) GetValidAccessData(token string) (AccessData, *HttpError) {
	access, err := s.Storage.LoadAccess(token)
	if err != nil {
		if httpErr, ok := err.(*HttpError); ok {
			return nil, httpErr
		}
		return nil, &HttpError{
			Status: http.StatusInternalServerError,
			Message: err.Error(),
		}
	}
	if access.GetClient() == nil {
		return nil, deferror.Get(E_UNAUTHORIZED_CLIENT)
	}
	if access.IsExpired() {
		return nil, deferror.Get(E_INVALID_GRANT)
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
func (s *Server) GetValidRefresh(token string) (AccessData, error) {
	access, err := s.Storage.LoadRefresh(token)
	if err != nil {
		if httpErr, ok := err.(*HttpError); ok {
			return nil, httpErr
		}
		return nil, &HttpError{
			Status: http.StatusInternalServerError,
			Message: err.Error(),
		}
	}
	if access.GetClient() == nil {
		return nil, deferror.Get(E_UNAUTHORIZED_CLIENT)
	}
	return access, nil
}
