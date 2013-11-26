package osin

import (
	"net/http"
	"time"
)

type AccessRequestType string

const (
	AUTHORIZATION_CODE AccessRequestType = "authorization_code"
	REFRESH_TOKEN                        = "refresh_token"
	PASSWORD                             = "password"
	CLIENT_CREDENTIALS                   = "client_credentials"
	IMPLICIT                             = "__implicit"
)

// Access request information
type AccessRequest struct {
	Type          AccessRequestType
	Code          string
	Client        Client
	AuthorizeData AuthorizeData
	AccessData    AccessData
	RedirectUri   string
	Scope         string
	Username      string
	Password      string

	// Set if request is authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default
	Expiration int32

	// Set if a refresh token should be generated
	GenerateRefresh bool

	// Data to be passed to storage. Not used by the library.
	UserData interface{}
}

// AccessData is any struct that impelements getters and setters for
// access information.
type AccessData interface {
	GetClient() Client
	SetClient(Client)

	GetAuthorizeData() AuthorizeData
	SetAuthorizeData(AuthorizeData)

	GetAccessData() AccessData
	SetAccessData(AccessData)

	GetAccessToken() string
	SetAccessToken(string)

	GetRefreshToken() string
	SetRefreshToken(string)

	GetExpiresIn() int32
	SetExpiresIn(int32)

	GetScope() string
	SetScope(string)

	GetRedirectUri() string
	SetRedirectUri(string)

	GetCreatedAt() time.Time
	SetCreatedAt(time.Time)

	ExpiresAt() time.Time

	IsExpired() bool
}

// OsinAccessData is the default AccessData type.
type OsinAccessData struct {
	// Client information
	Client Client

	// Authorize data, for authorization code
	AuthorizeData AuthorizeData

	// Previous access data, for refresh token
	AccessData AccessData

	// Access token
	AccessToken string

	// Refresh Token. Can be blank
	RefreshToken string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect Uri from request
	RedirectUri string

	// Date created
	CreatedAt time.Time
}

func (data *OsinAccessData) GetClient() Client {
	return data.Client
}

func (data *OsinAccessData) SetClient(client Client) {
	data.Client = client
}

func (data *OsinAccessData) GetAuthorizeData() AuthorizeData {
	return data.AuthorizeData
}

func (data *OsinAccessData) SetAuthorizeData(authData AuthorizeData) {
	data.AuthorizeData = authData
}

func (data *OsinAccessData) GetAccessData() AccessData {
	return data.AccessData
}

func (data *OsinAccessData) SetAccessData(accessData AccessData) {
	data.AccessData = accessData
}

func (data *OsinAccessData) GetAccessToken() string {
	return data.AccessToken
}

func (data *OsinAccessData) SetAccessToken(token string) {
	data.AccessToken = token
}

func (data *OsinAccessData) GetRefreshToken() string {
	return data.RefreshToken
}

func (data *OsinAccessData) SetRefreshToken(token string) {
	data.RefreshToken = token
}

func (data *OsinAccessData) GetExpiresIn() int32 {
	return data.ExpiresIn
}

func (data *OsinAccessData) SetExpiresIn(seconds int32) {
	data.ExpiresIn = seconds
}

func (data *OsinAccessData) GetScope() string {
	return data.Scope
}

func (data *OsinAccessData) SetScope(scope string) {
	data.Scope = scope
}

func (data *OsinAccessData) GetRedirectUri() string {
	return data.RedirectUri
}

func (data *OsinAccessData) SetRedirectUri(uri string) {
	data.RedirectUri = uri
}

func (data *OsinAccessData) GetCreatedAt() time.Time {
	return data.CreatedAt
}

func (data *OsinAccessData) SetCreatedAt(timestamp time.Time) {
	data.CreatedAt = timestamp
}

// ExpiresAt returns this AccessData's expiration timestamp.
func (data *OsinAccessData) ExpiresAt() time.Time {
	return data.GetCreatedAt().Add(time.Duration(data.GetExpiresIn()) * time.Second)
}

// IsExpired returns true if this AccessData is expired, false
// otherwise.
func (data *OsinAccessData) IsExpired() bool {
	return data.ExpiresAt().Before(time.Now())
}

// Access token generator interface
type AccessTokenGen interface {
	GenerateAccessToken(generaterefresh bool) (accesstoken string, refreshtoken string, err error)
}

// Access token request
func (s *Server) HandleAccessRequest(w *Response, r *http.Request) *AccessRequest {
	// Only allow GET or POST
	if r.Method == "GET" {
		if !s.Config.AllowGetAccessRequest {
			w.SetError(E_INVALID_REQUEST, "")
			return nil
		}
	} else if r.Method != "POST" {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	r.ParseForm()

	grantType := AccessRequestType(r.Form.Get("grant_type"))
	if s.Config.AllowedAccessTypes.Exists(grantType) {
		switch grantType {
		case AUTHORIZATION_CODE:
			return s.handleAccessRequestAuthorizationCode(w, r)
		case REFRESH_TOKEN:
			return s.handleAccessRequestRefreshToken(w, r)
		case PASSWORD:
			return s.handleAccessRequestPassword(w, r)
		case CLIENT_CREDENTIALS:
			return s.handleAccessRequestClientCredentials(w, r)
		}
	}

	w.SetError(E_UNSUPPORTED_GRANT_TYPE, "")
	return nil
}

func (s *Server) handleAccessRequestAuthorizationCode(w *Response, r *http.Request) *AccessRequest {
	auth, err := GetValidAuth(r, s.Config.AllowClientSecretInParams, w)
	if err != nil {
		return nil
	}

	ret := &AccessRequest{
		Type:            AUTHORIZATION_CODE,
		Code:            r.Form.Get("code"),
		RedirectUri:     r.Form.Get("redirect_uri"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	if ret.Code == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	ret.Client, err = s.GetValidClientWithSecret(auth.Username, auth.Password, w)
	if err != nil {
		return nil
	}

	ret.AuthorizeData, err = s.GetValidAuthData(ret.Code, w)
	if err != nil {
		return nil
	}

	if ret.AuthorizeData.GetClient().GetId() != ret.Client.GetId() {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	if ret.RedirectUri == "" {
		ret.RedirectUri = ret.Client.GetRedirectUri()
	}
	if err = ValidateUri(ret.Client.GetRedirectUri(), ret.RedirectUri); err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if ret.AuthorizeData.GetRedirectUri() != ret.RedirectUri {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	// set rest of data
	ret.Scope = ret.AuthorizeData.GetScope()

	return ret
}

func (s *Server) handleAccessRequestRefreshToken(w *Response, r *http.Request) *AccessRequest {
	auth, err := GetValidAuth(r, s.Config.AllowClientSecretInParams, w)
	if err != nil {
		return nil
	}

	ret := &AccessRequest{
		Type:            REFRESH_TOKEN,
		Code:            r.Form.Get("refresh_token"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	if ret.Code == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	ret.Client, err = s.GetValidClientWithSecret(auth.Username, auth.Password, w)
	if err != nil {
		return nil
	}

	ret.AccessData, err = s.GetValidRefresh(ret.Code, w)
	if err != nil {
		return nil
	}

	if ret.AccessData.GetClient().GetId() != ret.Client.GetId() {
		w.SetError(E_INVALID_CLIENT, "")
		return nil
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
func (s *Server) handleAccessRequestPassword(w *Response, r *http.Request) *AccessRequest {

	ret := &AccessRequest{
		Type:            PASSWORD,
		Username:        r.Form.Get("username"),
		Password:        r.Form.Get("password"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	if ret.Username == "" || ret.Password == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	var err error

	ret.Client, err = s.GetValidClient(r.Form.Get("client_id"), w)
	if err != nil {
		return nil
	}

	ret.RedirectUri = ret.Client.GetRedirectUri()

	return ret
}

func (s *Server) handleAccessRequestClientCredentials(w *Response, r *http.Request) *AccessRequest {
	auth, err := GetValidAuth(r, s.Config.AllowClientSecretInParams, w)
	if err != nil {
		return nil
	}

	ret := &AccessRequest{
		Type:            CLIENT_CREDENTIALS,
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	ret.Client, err = s.GetValidClientWithSecret(auth.Username, auth.Password, w)
	if err != nil {
		return nil
	}

	ret.RedirectUri = ret.Client.GetRedirectUri()

	return ret
}

func (s *Server) FinishAccessRequest(w *Response, r *http.Request, ar *AccessRequest, targets ...interface{}) {
	if w.IsError {
		return
	}

	if ar.Authorized {
		var target AccessData
		if len(targets) > 0 {
			target = targets[0].(AccessData)
		} else {
			target = new(OsinAccessData)
		}
		target.SetClient(ar.Client)
		target.SetAuthorizeData(ar.AuthorizeData)
		target.SetAccessData(ar.AccessData)
		target.SetRedirectUri(r.Form.Get("redirect_uri"))
		target.SetCreatedAt(time.Now())
		target.SetExpiresIn(ar.Expiration)

		accessToken, refreshToken, err := s.AccessTokenGen.GenerateAccessToken(ar.GenerateRefresh)
		if err != nil {
			w.SetError(E_SERVER_ERROR, "")
			w.InternalError = err
			return
		}
		target.SetAccessToken(accessToken)
		target.SetRefreshToken(refreshToken)

		if err = s.Storage.SaveAccess(target); err != nil {
			w.SetError(E_SERVER_ERROR, "")
			w.InternalError = err
			return
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

		w.Output["access_token"] = target.GetAccessToken()
		w.Output["token_type"] = s.Config.TokenType
		w.Output["expires_in"] = target.GetExpiresIn()
		if target.GetRefreshToken() != "" {
			w.Output["refresh_token"] = target.GetRefreshToken()
		}
		if ar.Scope != "" {
			w.Output["scope"] = ar.Scope
		}
	} else {
		w.SetError(E_ACCESS_DENIED, "")
	}
}
