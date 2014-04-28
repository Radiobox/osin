package osin

import "time"

type AccessRequestType string

const (
	AUTHORIZATION_CODE AccessRequestType = "authorization_code"
	REFRESH_TOKEN                        = "refresh_token"
	PASSWORD                             = "password"
	CLIENT_CREDENTIALS                   = "client_credentials"
	IMPLICIT                             = "__implicit"
)

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

// BasicAccessData is a very basic struct type that implements
// AccessData.  Most likely, this doesn't contain enough information
// for your needs (at minimum, it should have data about the user).
// You should embed this struct into your own struct, so that you can
// add whatever extra data you need.
type BasicAccessData struct {
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

func (data *BasicAccessData) GetClient() Client {
	return data.Client
}

func (data *BasicAccessData) SetClient(client Client) {
	data.Client = client
}

func (data *BasicAccessData) GetAuthorizeData() AuthorizeData {
	return data.AuthorizeData
}

func (data *BasicAccessData) SetAuthorizeData(authData AuthorizeData) {
	data.AuthorizeData = authData
}

func (data *BasicAccessData) GetAccessData() AccessData {
	return data.AccessData
}

func (data *BasicAccessData) SetAccessData(accessData AccessData) {
	data.AccessData = accessData
}

func (data *BasicAccessData) GetAccessToken() string {
	return data.AccessToken
}

func (data *BasicAccessData) SetAccessToken(token string) {
	data.AccessToken = token
}

func (data *BasicAccessData) GetRefreshToken() string {
	return data.RefreshToken
}

func (data *BasicAccessData) SetRefreshToken(token string) {
	data.RefreshToken = token
}

func (data *BasicAccessData) GetExpiresIn() int32 {
	return data.ExpiresIn
}

func (data *BasicAccessData) SetExpiresIn(seconds int32) {
	data.ExpiresIn = seconds
}

func (data *BasicAccessData) GetScope() string {
	return data.Scope
}

func (data *BasicAccessData) SetScope(scope string) {
	data.Scope = scope
}

func (data *BasicAccessData) GetRedirectUri() string {
	return data.RedirectUri
}

func (data *BasicAccessData) SetRedirectUri(uri string) {
	data.RedirectUri = uri
}

func (data *BasicAccessData) GetCreatedAt() time.Time {
	return data.CreatedAt
}

func (data *BasicAccessData) SetCreatedAt(timestamp time.Time) {
	data.CreatedAt = timestamp
}

// ExpiresAt returns this AccessData's expiration timestamp.
func (data *BasicAccessData) ExpiresAt() time.Time {
	return data.GetCreatedAt().Add(time.Duration(data.GetExpiresIn()) * time.Second)
}

// IsExpired returns true if this AccessData is expired, false
// otherwise.
func (data *BasicAccessData) IsExpired() bool {
	return data.ExpiresAt().Before(time.Now())
}
