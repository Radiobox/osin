package osin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func ValidateUri(baseUri string, redirectUri string) *HttpError {
	if baseUri == "" || redirectUri == "" {
		return &HttpError{
			Status:  http.StatusBadRequest,
			Message: "urls cannot be blank.",
		}
	}

	base, err := url.Parse(baseUri)
	if err != nil {
		return &HttpError{
			Status:  http.StatusBadRequest,
			Message: "Url parse error: " + err.Error(),
		}
	}

	redirect, err := url.Parse(redirectUri)
	if err != nil {
		return &HttpError{
			Status:  http.StatusBadRequest,
			Message: "Redirect url parse error: " + err.Error(),
		}
	}

	if base.Fragment != "" || redirect.Fragment != "" {
		return &HttpError{
			Status:  http.StatusBadRequest,
			Message: "Url must not include fragment.",
		}
	}

	validRedirect := base.Scheme == redirect.Scheme && base.Host == redirect.Host &&
		len(redirect.Path) >= len(base.Path) && strings.HasPrefix(redirect.Path, base.Path)
	if !validRedirect {
		return &HttpError{
			Status:  http.StatusUnauthorized,
			Message: fmt.Sprintf("Urls don't validate: %s / %s", baseUri, redirectUri),
		}
	}
	return nil
}
