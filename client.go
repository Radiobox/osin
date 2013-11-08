package osin

// Client is any struct type that has getters and setters for some
// required Client parameters.
type Client interface {
	Id() string
	SetId(string)

	Secret() string
	SetSecret(string)

	RedirectUri() string
	SetRedirectUri(string)
}

// OsinClient is the default client type.
type OsinClient struct {
	// Client id
	id string

	// Client secrent
	secret string

	// Base client uri
	redirectUri string
}

func (client *OsinClient) Id() string {
	return client.id
}

func (client *OsinClient) SetId(id string) {
	client.id = id
}

func (client *OsinClient) Secret() string {
	return client.secret
}

func (client *OsinClient) SetSecret(secret string) {
	client.secret = secret
}

func (client *OsinClient) RedirectUri() string {
	return client.redirectUri
}

func (client *OsinClient) SetRedirectUri(uri string) {
	client.redirectUri = uri
}
