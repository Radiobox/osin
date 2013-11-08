package osin

import (
	"code.google.com/p/go-uuid/uuid"
	"encoding/base64"
)

// Default authorization token generator
type AuthorizeTokenGenDefault struct {
}

func (a *AuthorizeTokenGenDefault) GenerateAuthorizeToken() (ret string, err error) {
	token := uuid.New()
	return base64.StdEncoding.EncodeToString([]byte(token)), nil
}

// Default authorization token generator
type AccessTokenGenDefault struct {
}

func (a *AccessTokenGenDefault) GenerateAccessToken(generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	accesstoken = uuid.New()
	accesstoken = base64.StdEncoding.EncodeToString([]byte(accesstoken))

	if generaterefresh {
		refreshtoken = uuid.New()
		refreshtoken = base64.StdEncoding.EncodeToString([]byte(refreshtoken))
	}
	return
}
