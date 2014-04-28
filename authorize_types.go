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

// BasicAuthorizeData is the default AuthorizeData type.
type BasicAuthorizeData struct {
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

func (data *BasicAuthorizeData) GetClient() Client {
	return data.Client
}

func (data *BasicAuthorizeData) SetClient(client Client) {
	data.Client = client
}

func (data *BasicAuthorizeData) GetCode() string {
	return data.Code
}

func (data *BasicAuthorizeData) SetCode(code string) {
	data.Code = code
}

func (data *BasicAuthorizeData) GetExpiresIn() int32 {
	return data.ExpiresIn
}

func (data *BasicAuthorizeData) SetExpiresIn(seconds int32) {
	data.ExpiresIn = seconds
}

func (data *BasicAuthorizeData) GetScope() string {
	return data.Scope
}

func (data *BasicAuthorizeData) SetScope(scope string) {
	data.Scope = scope
}

func (data *BasicAuthorizeData) GetRedirectUri() string {
	return data.RedirectUri
}

func (data *BasicAuthorizeData) SetRedirectUri(uri string) {
	data.RedirectUri = uri
}

func (data *BasicAuthorizeData) GetState() string {
	return data.State
}

func (data *BasicAuthorizeData) SetState(state string) {
	data.State = state
}

func (data *BasicAuthorizeData) GetCreatedAt() time.Time {
	return data.CreatedAt
}

func (data *BasicAuthorizeData) SetCreatedAt(timestamp time.Time) {
	data.CreatedAt = timestamp
}

// ExpiresAt returns this AuthorizeData's expiration timestamp.
func (data *BasicAuthorizeData) ExpiresAt() time.Time {
	return data.GetCreatedAt().Add(time.Duration(data.GetExpiresIn()) * time.Second)
}

// IsExpired returns true if this AuthorizeData is expired, false
// otherwise.
func (data *BasicAuthorizeData) IsExpired() bool {
	return data.ExpiresAt().Before(time.Now())
}
