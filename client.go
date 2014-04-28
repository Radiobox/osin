package osin

// Client is any struct type that has getters and setters for some
// required Client parameters.
type Client interface {
	GetId() string
	SetId(string)

	GetSecret() string
	SetSecret(string)

	GetRedirectUri() string
	SetRedirectUri(string)
}

// BasicClient is the default client type.
type BasicClient struct {
	// Client id
	Id string

	// Client secrent
	Secret string

	// Base client uri
	RedirectUri string
}

func (client *BasicClient) GetId() string {
	return client.Id
}

func (client *BasicClient) SetId(id string) {
	client.Id = id
}

func (client *BasicClient) GetSecret() string {
	return client.Secret
}

func (client *BasicClient) SetSecret(secret string) {
	client.Secret = secret
}

func (client *BasicClient) GetRedirectUri() string {
	return client.RedirectUri
}

func (client *BasicClient) SetRedirectUri(uri string) {
	client.RedirectUri = uri
}
