package osin

import "time"

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
