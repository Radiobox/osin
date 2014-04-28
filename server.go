package osin

import ()

// OAuth2 server class
type Server struct {
	Config            *ServerConfig
	Storage           Storage
	AuthorizeTokenGen AuthorizeTokenGen
	AccessTokenGen    AccessTokenGen
}

// Creates a new server instance
func NewServer(config *ServerConfig, storage Storage) *Server {
	return &Server{
		Config:            config,
		Storage:           storage,
		AuthorizeTokenGen: &AuthorizeTokenGenDefault{},
		AccessTokenGen:    &AccessTokenGenDefault{},
	}
}
