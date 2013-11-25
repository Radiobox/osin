package osin

import (
	"net/http"
	"time"
)

type AuthorizeRequestType string

const (
	CODE  AuthorizeRequestType = "code"
	TOKEN                      = "token"
)

// Authorize request information
type AuthorizeRequest struct {
	Type        AuthorizeRequestType
	Client      Client
	Scope       string
	RedirectUri string
	State       string

	// Set if request is authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default.
	// If type = TOKEN, this expiration will be for the ACCESS token.
	Expiration int32
}

// AuthorizeData is any struct that implements getters and setters for
// authorization data, as well as expiration methods.
type AuthorizeData interface {
	GetClient() Client
	SetClient(Client)

	GetCode() string
	SetCode(string)

	GetExpiresIn() int32
	SetExpiresIn(int32)

	GetScope() string
	SetScope(string)

	GetRedirectUri() string
	SetRedirectUri(string)

	GetState() string
	SetState(string)

	GetCreatedAt() time.Time
	SetCreatedAt(time.Time)

	IsExpired() bool

	ExpiresAt() time.Time
}

// OsinAuthorizeData is the default AuthorizeData type.
type OsinAuthorizeData struct {
	// Client information
	Client Client

	// Authorization code
	Code string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect Uri from request
	RedirectUri string

	// State data from request
	State string

	// Date created
	CreatedAt time.Time
}

func (data *OsinAuthorizeData) GetClient() Client {
	return data.Client
}

func (data *OsinAuthorizeData) SetClient(client Client) {
	data.Client = client
}

func (data *OsinAuthorizeData) GetCode() string {
	return data.Code
}

func (data *OsinAuthorizeData) SetCode(code string) {
	data.Code = code
}

func (data *OsinAuthorizeData) GetExpiresIn() int32 {
	return data.ExpiresIn
}

func (data *OsinAuthorizeData) SetExpiresIn(seconds int32) {
	data.ExpiresIn = seconds
}

func (data *OsinAuthorizeData) GetScope() string {
	return data.Scope
}

func (data *OsinAuthorizeData) SetScope(scope string) {
	data.Scope = scope
}

func (data *OsinAuthorizeData) GetRedirectUri() string {
	return data.RedirectUri
}

func (data *OsinAuthorizeData) SetRedirectUri(uri string) {
	data.RedirectUri = uri
}

func (data *OsinAuthorizeData) GetState() string {
	return data.State
}

func (data *OsinAuthorizeData) SetState(state string) {
	data.State = state
}

func (data *OsinAuthorizeData) GetCreatedAt() time.Time {
	return data.CreatedAt
}

func (data *OsinAuthorizeData) SetCreatedAt(timestamp time.Time) {
	data.CreatedAt = timestamp
}

// ExpiresAt returns this AuthorizeData's expiration timestamp.
func (data *OsinAuthorizeData) ExpiresAt() time.Time {
	return data.GetCreatedAt().Add(time.Duration(data.GetExpiresIn()) * time.Second)
}

// IsExpired returns true if this AuthorizeData is expired, false
// otherwise.
func (data *OsinAuthorizeData) IsExpired() bool {
	return data.ExpiresAt().Before(time.Now())
}

// Authorization token generator interface
type AuthorizeTokenGen interface {
	GenerateAuthorizeToken() (string, error)
}

// Authorize request
func (s *Server) HandleAuthorizeRequest(w *Response, r *http.Request) *AuthorizeRequest {
	r.ParseForm()

	requestType := AuthorizeRequestType(r.Form.Get("response_type"))
	if s.Config.AllowedAuthorizeTypes.Exists(requestType) {
		switch requestType {
		case CODE:
			return s.handleAuthorizeRequestCode(w, r)
		case TOKEN:
			return s.handleAuthorizeRequestToken(w, r)
		}
	}

	w.SetError(E_UNSUPPORTED_RESPONSE_TYPE, "")
	return nil
}

func (s *Server) handleAuthorizeRequestCode(w *Response, r *http.Request) *AuthorizeRequest {
	ret := &AuthorizeRequest{
		Type:        CODE,
		State:       r.Form.Get("state"),
		Scope:       r.Form.Get("scope"),
		RedirectUri: r.Form.Get("redirect_uri"),
		Authorized:  false,
		Expiration:  s.Config.AuthorizationExpiration,
	}

	var err error

	ret.Client, err = s.GetValidClient(r.Form.Get("client_id"), w)
	if err != nil {
		return nil
	}

	w.SetRedirect(ret.Client.GetRedirectUri())

	if ret.RedirectUri == "" {
		ret.RedirectUri = ret.Client.GetRedirectUri()
	}
	if err = ValidateUri(ret.Client.GetRedirectUri(), ret.RedirectUri); err != nil {
		w.SetErrorState(E_INVALID_REQUEST, "", ret.State)
		w.InternalError = err
		return nil
	}

	return ret
}

func (s *Server) handleAuthorizeRequestToken(w *Response, r *http.Request) *AuthorizeRequest {
	ret := &AuthorizeRequest{
		Type:        TOKEN,
		State:       r.Form.Get("state"),
		Scope:       r.Form.Get("scope"),
		RedirectUri: r.Form.Get("redirect_uri"),
		Authorized:  false,
		// this type will generate a token directly, use access token expiration instead.
		Expiration: s.Config.AccessExpiration,
	}

	var err error

	ret.Client, err = s.GetValidClient(r.Form.Get("client_id"), w)
	if err != nil {
		return nil
	}

	w.SetRedirect(ret.Client.GetRedirectUri())

	if ret.RedirectUri == "" {
		ret.RedirectUri = ret.Client.GetRedirectUri()
	}
	if err = ValidateUri(ret.Client.GetRedirectUri(), ret.RedirectUri); err != nil {
		w.SetErrorState(E_INVALID_REQUEST, "", ret.State)
		w.InternalError = err
		return nil
	}

	return ret
}

func (s *Server) FinishAuthorizeRequest(w *Response, r *http.Request, ar *AuthorizeRequest, targets ...interface{}) {
	if w.IsError {
		return
	}

	w.SetRedirect(ar.RedirectUri)

	if ar.Authorized {
		if ar.Type == TOKEN {
			w.SetRedirectFragment(true)

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

			s.FinishAccessRequest(w, r, ret, targets...)
		} else {
			var target AuthorizeData
			if len(targets) > 0 {
				target = targets[0].(AuthorizeData)
			} else {
				target = new(OsinAuthorizeData)
			}
			target.SetClient(ar.Client)
			target.SetCreatedAt(time.Now())
			target.SetExpiresIn(ar.Expiration)
			target.SetRedirectUri(ar.RedirectUri)
			target.SetState(ar.State)
			target.SetScope(ar.Scope)

			code, err := s.AuthorizeTokenGen.GenerateAuthorizeToken()
			if err != nil {
				w.SetErrorState(E_SERVER_ERROR, "", ar.State)
				w.InternalError = err
				return
			}
			target.SetCode(code)

			if err = s.Storage.SaveAuthorize(target); err != nil {
				w.SetErrorState(E_SERVER_ERROR, "", ar.State)
				w.InternalError = err
				return
			}

			w.Output["code"] = target.GetCode()
			w.Output["state"] = target.GetState()
		}
	} else {
		// redirect with error
		w.SetErrorState(E_ACCESS_DENIED, "", ar.State)
	}
}
