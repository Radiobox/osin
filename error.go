package osin

import (
	"errors"
	"fmt"
	"net/http"
)

type DefaultErrorId string

const (
	E_INVALID_REQUEST           = "invalid_request"
	E_UNAUTHORIZED_CLIENT       = "unauthorized_client"
	E_ACCESS_DENIED             = "access_denied"
	E_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
	E_INVALID_SCOPE             = "invalid_scope"
	E_SERVER_ERROR              = "server_error"
	E_TEMPORARILY_UNAVAILABLE   = "temporarily_unavailable"
	E_UNSUPPORTED_GRANT_TYPE    = "unsupported_grant_type"
	E_INVALID_GRANT             = "invalid_grant"
	E_INVALID_CLIENT            = "invalid_client"
)

var (
	deferror *DefaultErrors = NewDefaultErrors()
)

// An HttpError is an error with a Status.  In most cases, the Status
// field should be used as the response code of any http responses
// returning the error to a client.
type HttpError struct {
	Status int
	Message string
}

func (err HttpError) Error() string {
	return fmt.Sprintf("%d: %s", err.Status, err.Message)
}

// Default errors and messages
type DefaultErrors struct {
	errormap map[string]*HttpError
}

func NewDefaultErrors() *DefaultErrors {
	errMap := map[string]*HttpError{
		E_INVALID_REQUEST: &HttpError{
			Status: http.StatusBadRequest,
			Message: "The request is missing a required parameter, " +
				"includes an invalid parameter value, includes a " +
				"parameter more than once, or is otherwise malformed.",
		},
		E_UNAUTHORIZED_CLIENT: &HttpError{
			Status: http.StatusUnauthorized,
			Message: "The client is not authorized to request a token using this method.",
		},
		E_ACCESS_DENIED: &HttpError{
			Status: http.StatusUnauthorized,
			Message: "The resource owner or authorization server denied the request.",
		},
		E_UNSUPPORTED_RESPONSE_TYPE: &HttpError{
			Status: http.StatusNotAcceptable,
			Message: "The authorization server does not " +
				"support obtaining a token using this method.",
		},
		E_INVALID_SCOPE: &HttpError{
			Status: http.StatusBadRequest,
			Message: "The requested scope is invalid, unknown, or malformed.",
		},
		E_SERVER_ERROR: &HttpError{
			Status: http.StatusInternalServerError,
			Message: "The authorization server encountered an unexpected " +
				"condition that prevented it from fulfilling the request.",
		},
		E_TEMPORARILY_UNAVAILABLE: &HttpError{
			Status: http.StatusServiceUnavailable,
			Message: "The authorization server is currently " +
				"unable to handle the request due to a temporary overloading or maintenance of the server.",
		},
		E_UNSUPPORTED_GRANT_TYPE: &HttpError{
			Status: http.StatusNotAcceptable,
			Message: "The authorization grant type is not " +
				"supported by the authorization server.",
		}
		E_INVALID_GRANT: &HttpError{
			Status: http.StatusUnauthorized,
			Message: "The provided authorization grant (e.g., authorization " +
				"code, resource owner credentials, or refresh token is invalid, expired, revoked, does not " +
				"match the redirection URI used in the authorization request, or was issued to another client.",
		}
		E_INVALID_CLIENT: &HttpError{
			Status: http.StatusUnauthorized,
			Message: "Client authentication failed (e.g., unknown client, no " +
				"client authentication included, or unsupported authentication method.",
		}
	}
	return &DefaultErrors{errormap: errMap}
}

func (e *DefaultErrors) Get(id string) *HttpError {
	if m, ok := e.errormap[id]; ok {
		return m
	}
	return &HttpError{
		Status: http.StatusInternalServerError,
		Message: "Unrecognized error type: " + id,
	}
}
