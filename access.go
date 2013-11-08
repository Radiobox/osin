package osin

import (
	"errors"
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
	client Client

	// Authorize data, for authorization code
	authorizeData AuthorizeData

	// Previous access data, for refresh token
	accessData AccessData

	// Access token
	accessToken string

	// Refresh Token. Can be blank
	refreshToken string

	// Token expiration in seconds
	expiresIn int32

	// Requested scope
	scope string

	// Redirect Uri from request
	redirectUri string

	// Date created
	createdAt time.Time
}

func (data *OsinAccessData) Client() Client {
	return data.client
}

func (data *OsinAccessData) SetClient(client Client) {
	data.client = client
}

func (data *OsinAccessData) AuthorizeData() AuthorizeData {
	return data.authorizeData
}

func (data *OsinAccessData) SetAuthorizeData(authData AuthorizeData) {
	data.authorizeData = authData
}

func (data *OsinAccessData) AccessData() AccessData {
	return data.accessData
}

func (data *OsinAccessData) SetAccessData(accessData AccessData) {
	data.accessData = accessData
}

func (data *OsinAccessData) AccessToken() string {
	return data.accessToken
}

func (data *OsinAccessData) SetAccessToken(token string) {
	data.accessToken = token
}

func (data *OsinAccessData) RefreshToken() string {
	return data.refreshToken
}

func (data *OsinAccessData) SetRefreshToken(token string) {
	data.refreshToken = token
}

func (data *OsinAccessData) ExpiresIn() int32 {
	return data.expiresIn
}

func (data *OsinAccessData) SetExpiresIn(seconds int32) {
	data.expiresIn = seconds
}

func (data *OsinAccessData) Scope() string {
	return data.scope
}

func (data *OsinAccessData) SetScope(scope string) {
	data.scope = scope
}

func (data *OsinAccessData) RedirectUri() string {
	return data.redirectUri
}

func (data *OsinAccessData) SetRedirectUri(uri string) {
	data.redirectUri = uri
}

func (data *OsinAccessData) CreatedAt() time.Time {
	return data.createdAt
}

func (data *OsinAccessData) SetCreatedAt(timestamp time.Time) {
	data.createdAt = timestamp
}

// ExpiresAt returns this AccessData's expiration timestamp.
func (data *OsinAccessData) ExpiresAt() time.Time {
	return data.CreatedAt().Add(time.Duration(data.ExpiresIn()) * time.Second)
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
	// get client information from basic authentication
	auth, err := CheckClientAuth(r, s.Config.AllowClientSecretInParams)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if auth == nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = errors.New("Client authentication not sent")
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            AUTHORIZATION_CODE,
		Code:            r.Form.Get("code"),
		RedirectUri:     r.Form.Get("redirect_uri"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	// "code" is required
	if ret.Code == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// must have a valid client
	ret.Client, err = s.Storage.GetClient(auth.Username)
	if err != nil {
		w.SetError(E_SERVER_ERROR, "")
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.Secret() != auth.Password {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.RedirectUri() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}

	// must be a valid authorization code
	ret.AuthorizeData, err = s.Storage.LoadAuthorize(ret.Code)
	if err != nil {
		w.SetError(E_INVALID_GRANT, "")
		w.InternalError = err
		return nil
	}
	if ret.AuthorizeData.Client() == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AuthorizeData.Client().RedirectUri() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AuthorizeData.IsExpired() {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// code must be from the client
	if ret.AuthorizeData.Client().Id() != ret.Client.Id() {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// check redirect uri
	if ret.RedirectUri == "" {
		ret.RedirectUri = ret.Client.RedirectUri()
	}
	if err = ValidateUri(ret.Client.RedirectUri(), ret.RedirectUri); err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if ret.AuthorizeData.RedirectUri() != ret.RedirectUri {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	// set rest of data
	ret.Scope = ret.AuthorizeData.Scope()

	return ret
}

func (s *Server) handleAccessRequestRefreshToken(w *Response, r *http.Request) *AccessRequest {
	// get client information from basic authentication
	auth, err := CheckClientAuth(r, s.Config.AllowClientSecretInParams)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if auth == nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = errors.New("Client authentication not sent")
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            REFRESH_TOKEN,
		Code:            r.Form.Get("refresh_token"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	// "refresh_token" is required
	if ret.Code == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// must have a valid client
	ret.Client, err = s.Storage.GetClient(auth.Username)
	if err != nil {
		w.SetError(E_SERVER_ERROR, "")
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.Secret() != auth.Password {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.RedirectUri() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}

	// must be a valid refresh code
	ret.AccessData, err = s.Storage.LoadRefresh(ret.Code)
	if err != nil {
		w.SetError(E_INVALID_GRANT, "")
		w.InternalError = err
		return nil
	}
	if ret.AccessData.Client() == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AccessData.Client().RedirectUri() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}

	// client must be the safe as the previous token
	if ret.AccessData.Client().Id() != ret.Client.Id() {
		w.SetError(E_INVALID_CLIENT, "")
		return nil
	}

	// set rest of data
	ret.RedirectUri = ret.AccessData.RedirectUri()
	if ret.Scope == "" {
		ret.Scope = ret.AccessData.Scope()
	}

	return ret
}

func (s *Server) handleAccessRequestPassword(w *Response, r *http.Request) *AccessRequest {
	// get client information from basic authentication
	auth, err := CheckClientAuth(r, s.Config.AllowClientSecretInParams)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if auth == nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = errors.New("Client authentication not sent")
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            PASSWORD,
		Username:        r.Form.Get("username"),
		Password:        r.Form.Get("password"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	// "username" and "password" is required
	if ret.Username == "" || ret.Password == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// must have a valid client
	ret.Client, err = s.Storage.GetClient(auth.Username)
	if err != nil {
		w.SetError(E_SERVER_ERROR, "")
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.Secret() != auth.Password {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.RedirectUri() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}

	// set redirect uri
	ret.RedirectUri = ret.Client.RedirectUri()

	// set rest of data

	return ret
}

func (s *Server) handleAccessRequestClientCredentials(w *Response, r *http.Request) *AccessRequest {
	// get client information from basic authentication
	auth, err := CheckClientAuth(r, s.Config.AllowClientSecretInParams)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if auth == nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = errors.New("Client authentication not sent")
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            CLIENT_CREDENTIALS,
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	// must have a valid client
	ret.Client, err = s.Storage.GetClient(auth.Username)
	if err != nil {
		w.SetError(E_SERVER_ERROR, "")
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.Secret() != auth.Password {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.RedirectUri() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}

	// set redirect uri
	ret.RedirectUri = ret.Client.RedirectUri()

	// set rest of data

	return ret
}

func (s *Server) FinishAccessRequest(w *Response, r *http.Request, ar *AccessRequest, data ...AccessData) {
	if w.IsError {
		return
	}

	if ar.Authorized {
		var target AccessData
		if len(data) > 0 {
			target = data[0]
		} else {
			target = new(OsinAccessData)
		}
		target.SetClient(ar.Client)
		target.SetAuthorizeData(ar.AuthorizeData)
		target.SetAccessData(ar.AccessData)
		target.SetRedirectUri(r.Form.Get("redirect_uri"))
		target.SetCreatedAt(time.Now())
		target.SetExpiresIn(ar.Expiration)

		// generate access token
		accessToken, refreshToken, err := s.AccessTokenGen.GenerateAccessToken(ar.GenerateRefresh)
		target.SetAccessToken(accessToken)
		target.SetRefreshToken(refreshToken)
		if err != nil {
			w.SetError(E_SERVER_ERROR, "")
			w.InternalError = err
			return
		}

		// save access token
		if err = s.Storage.SaveAccess(target); err != nil {
			w.SetError(E_SERVER_ERROR, "")
			w.InternalError = err
			return
		}

		// remove authorization token
		if target.AuthorizeData() != nil {
			s.Storage.RemoveAuthorize(target.AuthorizeData().Code())
		}

		// remove previous access token
		if target.AccessData() != nil {
			if target.AccessData().RefreshToken() != "" {
				s.Storage.RemoveRefresh(target.AccessData().RefreshToken())
			}
			s.Storage.RemoveAccess(target.AccessData().AccessToken())
		}

		// output data
		w.Output["access_token"] = target.AccessToken()
		w.Output["token_type"] = s.Config.TokenType
		w.Output["expires_in"] = target.ExpiresIn()
		if target.RefreshToken() != "" {
			w.Output["refresh_token"] = target.RefreshToken()
		}
		if ar.Scope != "" {
			w.Output["scope"] = ar.Scope
		}
	} else {
		w.SetError(E_ACCESS_DENIED, "")
	}
}
