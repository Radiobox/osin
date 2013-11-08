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
	Client() Client
	SetClient(Client)

	Code() string
	SetCode(string)

	ExpiresIn() int32
	SetExpiresIn(int32)

	Scope() string
	SetScope(string)

	RedirectUri() string
	SetRedirectUri(string)

	State() string
	SetState(string)

	CreatedAt() time.Time
	SetCreatedAt(time.Time)

	IsExpired() bool

	ExpiresAt() time.Time
}

// OsinAuthorizeData is the default AuthorizeData type.
type OsinAuthorizeData struct {
	// Client information
	client Client

	// Authorization code
	code string

	// Token expiration in seconds
	expiresIn int32

	// Requested scope
	scope string

	// Redirect Uri from request
	redirectUri string

	// State data from request
	state string

	// Date created
	createdAt time.Time
}

func (data *OsinAuthorizeData) Client() Client {
	return data.client
}

func (data *OsinAuthorizeData) SetClient(client Client) {
	data.client = client
}

func (data *OsinAuthorizeData) Code() string {
	return data.code
}

func (data *OsinAuthorizeData) SetCode(code string) {
	data.code = code
}

func (data *OsinAuthorizeData) ExpiresIn() int32 {
	return data.expiresIn
}

func (data *OsinAuthorizeData) SetExpiresIn(seconds int32) {
	data.expiresIn = seconds
}

func (data *OsinAuthorizeData) Scope() string {
	return data.scope
}

func (data *OsinAuthorizeData) SetScope(scope string) {
	data.scope = scope
}

func (data *OsinAuthorizeData) RedirectUri() string {
	return data.redirectUri
}

func (data *OsinAuthorizeData) SetRedirectUri(uri string) {
	data.redirectUri = uri
}

func (data *OsinAuthorizeData) State() string {
	return data.state
}

func (data *OsinAuthorizeData) SetState(state string) {
	data.state = state
}

func (data *OsinAuthorizeData) CreatedAt() time.Time {
	return data.createdAt
}

func (data *OsinAuthorizeData) SetCreatedAt(timestamp time.Time) {
	data.createdAt = timestamp
}

// ExpiresAt returns this AuthorizeData's expiration timestamp.
func (data *OsinAuthorizeData) ExpiresAt() time.Time {
	return data.CreatedAt().Add(time.Duration(data.ExpiresIn()) * time.Second)
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
	// create the authorization request
	ret := &AuthorizeRequest{
		Type:        CODE,
		State:       r.Form.Get("state"),
		Scope:       r.Form.Get("scope"),
		RedirectUri: r.Form.Get("redirect_uri"),
		Authorized:  false,
		Expiration:  s.Config.AuthorizationExpiration,
	}

	var err error

	// must have a valid client
	ret.Client, err = s.Storage.GetClient(r.Form.Get("client_id"))
	if err != nil {
		w.SetErrorState(E_SERVER_ERROR, "", ret.State)
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}
	if ret.Client.RedirectUri() == "" {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}

	// force redirect response to client redirecturl first
	w.SetRedirect(ret.Client.RedirectUri())

	// check redirect uri
	if ret.RedirectUri == "" {
		ret.RedirectUri = ret.Client.RedirectUri()
	}
	if err = ValidateUri(ret.Client.RedirectUri(), ret.RedirectUri); err != nil {
		w.SetErrorState(E_INVALID_REQUEST, "", ret.State)
		w.InternalError = err
		return nil
	}

	return ret
}

func (s *Server) handleAuthorizeRequestToken(w *Response, r *http.Request) *AuthorizeRequest {
	// create the authorization request
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

	// must have a valid client
	ret.Client, err = s.Storage.GetClient(r.Form.Get("client_id"))
	if err != nil {
		w.SetErrorState(E_SERVER_ERROR, "", ret.State)
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}
	if ret.Client.RedirectUri() == "" {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}

	// force redirect response to client redirecturl first
	w.SetRedirect(ret.Client.RedirectUri())

	// check redirect uri
	if ret.RedirectUri == "" {
		ret.RedirectUri = ret.Client.RedirectUri()
	}
	if err = ValidateUri(ret.Client.RedirectUri(), ret.RedirectUri); err != nil {
		w.SetErrorState(E_INVALID_REQUEST, "", ret.State)
		w.InternalError = err
		return nil
	}

	return ret
}

func (s *Server) FinishAuthorizeRequest(w *Response, r *http.Request, ar *AuthorizeRequest, data ...AuthorizeData) {
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

			s.FinishAccessRequest(w, r, ret)
		} else {
			var target AuthorizeData
			if len(data) > 0 {
				target = data[0]
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

			w.Output["code"] = target.Code
			w.Output["state"] = target.State
		}
	} else {
		// redirect with error
		w.SetErrorState(E_ACCESS_DENIED, "", ar.State)
	}
}
