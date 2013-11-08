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

// OsinClient is the default client type.
type OsinClient struct {
	// Client id
	Id string

	// Client secrent
	Secret string

	// Base client uri
	RedirectUri string
}

func (client *OsinClient) GetId() string {
	return client.Id
}

func (client *OsinClient) SetId(id string) {
	client.Id = id
}

func (client *OsinClient) GetSecret() string {
	return client.Secret
}

func (client *OsinClient) SetSecret(secret string) {
	client.Secret = secret
}

func (client *OsinClient) GetRedirectUri() string {
	return client.RedirectUri
}

func (client *OsinClient) SetRedirectUri(uri string) {
	client.RedirectUri = uri
}
