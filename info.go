package osin

import (
	"net/http"
	"time"
)

// Info request information
type InfoRequest struct {
	Code       string
	AccessData AccessData
}

// Information request.
// NOT an RFC specification.
func (s *Server) HandleInfoRequest(w *Response, r *http.Request) *InfoRequest {
	r.ParseForm()

	// generate info request
	ret := &InfoRequest{
		Code: r.Form.Get("code"),
	}

	if ret.Code == "" {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	var err error

	ret.AccessData, err = s.GetValidAccessData(ret.Code, w)
	if err != nil {
		return nil
	}

	return ret
}

func (s *Server) FinishInfoRequest(w *Response, r *http.Request, ir *InfoRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// output data
	w.Output["access_token"] = ir.AccessData.GetAccessToken()
	w.Output["token_type"] = s.Config.TokenType
	w.Output["expires_in"] = ir.AccessData.ExpiresAt().Sub(time.Now()) / time.Second
	if ir.AccessData.GetRefreshToken() != "" {
		w.Output["refresh_token"] = ir.AccessData.GetRefreshToken()
	}
	if ir.AccessData.GetScope() != "" {
		w.Output["scope"] = ir.AccessData.GetScope()
	}
}
