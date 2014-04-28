package osin

import (
	"github.com/stretchr/objx"
	"net/http"
	"time"
)

type InfoRequest struct {
	Code       string
	AccessData AccessData
}

func (s *Server) HandleInfoRequest(r *http.Request) (*InfoRequest, *HttpError) {
	r.ParseForm()

	ret := &InfoRequest{
		Code: r.Form.Get("code"),
	}

	if ret.Code == "" {
		return nil, deferror.Get(E_INVALID_REQUEST)
	}

	var err *HttpError

	ret.AccessData, err = s.GetValidAccessData(ret.Code)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (s *Server) FinishInfoRequest(r *http.Request, ir *InfoRequest) objx.Map {
	response := objx.Map{
		"access_token": ir.AccessData.GetAccessToken(),
		"token_type":   s.Config.TokenType,
		"expires_in":   ir.AccessData.ExpiresAt().Sub(time.Now()) / time.Second,
	}
	if ir.AccessData.GetRefreshToken() != "" {
		response.Set("refresh_token", ir.AccessData.GetRefreshToken())
	}
	if ir.AccessData.GetScope() != "" {
		response.Set("scope", ir.AccessData.GetScope())
	}
	return response
}
