package osin

import (
	"net/http"
	"time"
	"github.com/stretchr/objx"
)

// Access token generator interface
type AccessTokenGen interface {
	GenerateAccessToken(generaterefresh bool) (accesstoken string, refreshtoken string, err error)
}

// HandleAccessRequest takes a *http.Request and a map of input
// parameters, and returns a *AccessRequest representing the request
// for an access token and a *HttpError if any error is encountered.
func (s *Server) HandleAccessRequest(request *http.Request, params objx.Map) (*AccessRequest, *HttpError) {
	// Always allow POST.  Only allow GET when the config says it's
	// allowed.
	if request.Method != "POST" && (request.Method != "GET" || !s.Config.AllowGetAccessRequest) {
		return nil, deferror.Get(E_INVALID_REQUEST)
	}

	grantType := AccessRequestType(params.Get("grant_type").Str())
	if s.Config.AllowedAccessTypes.Exists(grantType) {
		switch grantType {
		case AUTHORIZATION_CODE:
			return s.handleAccessRequestAuthorizationCode(request, params)
		case REFRESH_TOKEN:
			return s.handleAccessRequestRefreshToken(request, params)
		case PASSWORD:
			return s.handleAccessRequestPassword(request, params)
		case CLIENT_CREDENTIALS:
			return s.handleAccessRequestClientCredentials(request, params)
		}
	}

	return nil, deferror.Get(E_UNSUPPORTED_GRANT_TYPE)
}

func (s *Server) handleAccessRequestAuthorizationCode(request *http.Request, params objx.Map) (*AccessRequest, *HttpError) {
	auth, err := GetValidAuth(request, params, s.Config.AllowClientSecretInParams)
	if err != nil {
		return nil, err
	}

	ret := &AccessRequest{
		Type:            AUTHORIZATION_CODE,
		Code:            params.Get("code").Str(),
		RedirectUri:     params.Get("redirect_uri").Str(),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	if ret.Code == "" {
		return nil, deferror.Get(E_INVALID_GRANT)
	}

	ret.Client, err = s.GetValidClientWithSecret(auth.Username, auth.Password)
	if err != nil {
		return nil, err
	}

	ret.AuthorizeData, err = s.GetValidAuthData(ret.Code)
	if err != nil {
		return nil, err
	}

	if ret.AuthorizeData.GetClient().GetId() != ret.Client.GetId() {
		return nil, deferror.Get(E_INVALID_GRANT)
	}

	if ret.RedirectUri == "" {
		ret.RedirectUri = ret.Client.GetRedirectUri()
	}
	if err = ValidateUri(ret.Client.GetRedirectUri(), ret.RedirectUri); err != nil {
		return nil, err
	}
	if ret.AuthorizeData.GetRedirectUri() != ret.RedirectUri {
		return nil, deferror.Get(E_INVALID_REQUEST)
	}

	ret.Scope = ret.AuthorizeData.GetScope()
	return ret
}

func (s *Server) handleAccessRequestRefreshToken(request *http.Request, params objx.Map) (*AccessRequest, *HttpError) {
	ret := &AccessRequest{
		Type:            REFRESH_TOKEN,
		Code:            params.Get("refresh_token").Str(),
		Scope:           params.Get("scope").Str(),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	if ret.Code == "" {
		return nil, deferror.Get(E_INVALID_GRANT)
	}

	var err error
	ret.Client, err = s.GetValidClient(params.Get("client_id").Str())
	if err != nil {
		return nil, err
	}

	ret.AccessData, err = s.GetValidRefresh(ret.Code)
	if err != nil {
		return nil, err
	}

	if ret.AccessData.GetClient().GetId() != ret.Client.GetId() {
		return nil, deferror.Get(E_INVALID_CLIENT)
	}

	ret.RedirectUri = ret.AccessData.GetRedirectUri()
	if ret.Scope == "" {
		ret.Scope = ret.AccessData.GetScope()
	}

	return ret
}

// handleAccessRequestPassword handles access requests that POST a
// username and password directly to the token end point.  This is
// usually a call from a client-side application or script, so we
// don't require a client secret, because it probably can't be secured
// properly, anyway.
func (s *Server) handleAccessRequestPassword(request *http.Request, params objx.Map) (*AccessRequest, *HttpError) {

	ret := &AccessRequest{
		Type:            PASSWORD,
		Username:        params.Get("username").Str(),
		Password:        params.Get("password").Str(),
		Scope:           params.Get("scope").Str(),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	if ret.Username == "" || ret.Password == "" {
		return nil, deferror.Get(E_INVALID_GRANT)
	}

	var err *HttpError
	ret.Client, err = s.GetValidClient(params.Get("client_id").Str())
	if err != nil {
		return nil, err
	}
	ret.RedirectUri = ret.Client.GetRedirectUri()
	return ret
}

func (s *Server) handleAccessRequestClientCredentials(request *http.Request, params objx.Map) (*AccessRequest, *HttpError) {
	auth, err := GetValidAuth(request, params, s.Config.AllowClientSecretInParams)
	if err != nil {
		return nil, err
	}

	ret := &AccessRequest{
		Type:            CLIENT_CREDENTIALS,
		Scope:           params.Get("scope").Str(),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	ret.Client, err = s.GetValidClientWithSecret(auth.Username, auth.Password)
	if err != nil {
		return nil, err
	}

	ret.RedirectUri = ret.Client.GetRedirectUri()

	return ret
}

func (s *Server) FinishAccessRequest(params objx.Map, ar *AccessRequest, target AccessData) (response objx.Map, httpErr *HttpError) {
	if ar.Authorized {
		target.SetClient(ar.Client)
		target.SetAuthorizeData(ar.AuthorizeData)
		target.SetAccessData(ar.AccessData)
		target.SetRedirectUri(params.Get("redirect_uri").Str())
		target.SetCreatedAt(time.Now())
		target.SetExpiresIn(ar.Expiration)

		accessToken, refreshToken, tokenErr := s.AccessTokenGen.GenerateAccessToken(ar.GenerateRefresh)
		if tokenErr != nil {
			return nil, tokenErr
		}
		target.SetAccessToken(accessToken)
		target.SetRefreshToken(refreshToken)

		if err := s.Storage.SaveAccess(target); err != nil {
			if httpErr, ok := err.(*HttpError); ok {
				return nil, httpErr
			} else {
				return nil, deferror.Get(err.Error())
			}
		}

		if target.GetAuthorizeData() != nil {
			s.Storage.RemoveAuthorize(target.GetAuthorizeData().GetCode())
		}

		if target.GetAccessData() != nil {
			if target.GetAccessData().GetRefreshToken() != "" {
				s.Storage.RemoveRefresh(target.GetAccessData().GetRefreshToken())
			}
			s.Storage.RemoveAccess(target.GetAccessData().GetAccessToken())
		}

		response := objx.Map{
			"access_token": target.GetAccessToken(),
			"token_type": s.Config.TokenType,
			"expires_in": target.GetExpiresIn(),
		}
		if target.GetRefreshToken() != "" {
			response.Set("refresh_token", target.GetRefreshToken())
		}
		if ar.Scope != "" {
			response.Set("scope", ar.Scope)
		}
		return response, nil
	}
	return nil, deferror.Get(E_ACCESS_DENIED)
}
