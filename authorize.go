package osin

import (
	"time"
	"github.com/stretchr/objx"
	"net/url"
	"net/http"
	"fmt"
)

// HandleAuthorizeRequest takes a *Response and an
// objx.Map of parameters, and returns a *AuthorizeRequest
// representing the request present in the *http.Request and
// parameters.
func (s *Server) HandleAuthorizeRequest(params objx.Map) (*AuthorizeRequest, *HttpError) {

	requestType := AuthorizeRequestType(params.Get("response_type").Str())
	if s.Config.AllowedAuthorizeTypes.Exists(requestType) {
		switch requestType {
		case CODE:
			return s.handleAuthorizeRequestCode(params)
		case TOKEN:
			return s.handleAuthorizeRequestToken(params)
		}
	}

	return nil, deferror.Get(E_UNSUPPORTED_RESPONSE_TYPE)
}

func (s *Server) handleAuthorizeRequestCode(params objx.Map) (*AuthorizeRequest, *HttpError) {
	ret := &AuthorizeRequest{
		Type:        CODE,
		State:       params.Get("state").Str(),
		Scope:       params.Get("scope").Str(),
		RedirectUri: params.Get("redirect_uri").Str(),
		Authorized:  false,
		Expiration:  s.Config.AuthorizationExpiration,
	}

	var err *HttpError

	ret.Client, err = s.GetValidClient(params.Get("client_id").Str())
	if err != nil {
		return nil, err
	}

	if ret.RedirectUri == "" {
		ret.RedirectUri = ret.Client.GetRedirectUri()
	}
	if err = ValidateUri(ret.Client.GetRedirectUri(), ret.RedirectUri); err != nil {
		return nil, err
	}

	return ret, nil
}

func (s *Server) handleAuthorizeRequestToken(params objx.Map) (*AuthorizeRequest, *HttpError) {
	ret := &AuthorizeRequest{
		Type:        TOKEN,
		State:       params.Get("state").Str(),
		Scope:       params.Get("scope").Str(),
		RedirectUri: params.Get("redirect_uri").Str(),
		Authorized:  false,
		// this type will generate a token directly, use access token expiration instead.
		Expiration: s.Config.AccessExpiration,
	}

	var err *HttpError

	ret.Client, err = s.GetValidClient(params.Get("client_id").Str())
	if err != nil {
		return nil, err
	}

	if ret.RedirectUri == "" {
		ret.RedirectUri = ret.Client.GetRedirectUri()
	}
	if err = ValidateUri(ret.Client.GetRedirectUri(), ret.RedirectUri); err != nil {
		return nil, err
	}

	return ret, nil
}

func (s *Server) FinishAuthorizeRequest(params objx.Map, ar *AuthorizeRequest, target interface{}) (redirect string, err *HttpError) {
	if ar.Authorized {
		redirectUrl, err := url.Parse(ar.RedirectUri)
		if err != nil {
			return "", &HttpError{
				Status: http.StatusInternalServerError,
				Message: "Could not parse previously parsed url: " + err.Error(),
			}
		}
		if ar.Type == TOKEN {
			access, ok := target.(AccessData)
			if !ok {
				return "", &HttpError{
					Status: http.StatusInternalServerError,
					Message: "Expected target to be AccessData.",
				}
			}

			ret := &AccessRequest{
				Type:            IMPLICIT,
				Code:            "",
				Client:          ar.Client,
				RedirectUri:     ar.RedirectUri,
				Scope:           ar.Scope,
				GenerateRefresh: false, // per the RFC, should NOT generate a refresh token in this case
				Authorized:      true,
				Expiration:      ar.Expiration,
			}

			response, err := s.FinishAccessRequest(params, ret, access)
			if err != nil {
				return "", err
			}
			query := redirectUrl.Query()
			for key, value := range response {
				query.Set(key, fmt.Sprint(value))
			}
			redirectUrl.RawQuery = ""
			redirectUrl.Fragment = query.Encode()
		} else {
			authData, ok := target.(AuthorizeData)
			if !ok {
				return "", &HttpError{
					Status: http.StatusInternalServerError,
					Message: "Expected target to be AuthorizeData",
				}
			}
			authData.SetClient(ar.Client)
			authData.SetCreatedAt(time.Now())
			authData.SetExpiresIn(ar.Expiration)
			authData.SetRedirectUri(ar.RedirectUri)
			authData.SetState(ar.State)
			authData.SetScope(ar.Scope)

			code, err := s.AuthorizeTokenGen.GenerateAuthorizeToken()
			if err != nil {
				return "", err
			}
			authData.SetCode(code)

			if saveErr := s.Storage.SaveAuthorize(authData); err != nil {
				if httpErr, ok := saveErr.(*HttpError); ok {
					return "", httpErr
				}
				return "", &HttpError{
					Status: http.StatusInternalServerError,
					Message: saveErr.Error(),
				}
			}

			query := redirectUrl.Query()
			query.Set("code", authData.GetCode())
			query.Set("state", authData.GetState())
			redirectUrl.RawQuery = query.Encode()
		}
		return redirectUrl.String(), nil
	}
	return "", deferror.Get(E_ACCESS_DENIED)
}
