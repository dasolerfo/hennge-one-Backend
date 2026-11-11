package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mockdb "github.com/dasolerfo/hennge-one-Backend.git/db/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestDashboardLoginHandler(t *testing.T) {
	const redirect = "https://dashboard.example.com/callback"

	testCases := []struct {
		name         string
		body         map[string]string
		tokenStatus  int
		useNonce     string // nonce embedded in the id_token returned by fake /token
		expectCalled bool
		expectStatus int
	}{
		{"OK", map[string]string{"code": "abc", "redirect_uri": redirect}, 200, "", true, 200},
		{"OKWithNonce", map[string]string{"code": "abc", "redirect_uri": redirect, "nonce": "n1"}, 200, "n1", true, 200},
		{"NonceMismatch", map[string]string{"code": "abc", "redirect_uri": redirect, "nonce": "n1"}, 200, "other", true, 400},
		{"TokenErrorRelayed", map[string]string{"code": "abc", "redirect_uri": redirect}, 400, "", true, 400},
		{"WrongRedirect", map[string]string{"code": "abc", "redirect_uri": "https://evil.example.com"}, 200, "", false, 400},
		{"MissingCode", map[string]string{"redirect_uri": redirect}, 200, "", false, 400},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			server := NewTestServer(t, mockdb.NewMockStore(ctrl))
			server.Config.DashboardClientID = "42"
			server.Config.DashboardClientSecret = "s3cret"
			server.Config.DashboardRedirectURI = redirect

			called := false
			fakeToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				require.NoError(t, r.ParseForm())
				require.Equal(t, "authorization_code", r.PostForm.Get("grant_type"))
				require.Equal(t, "42", r.PostForm.Get("client_id"))
				require.Equal(t, "s3cret", r.PostForm.Get("client_secret"))
				require.Equal(t, "abc", r.PostForm.Get("code"))
				require.Equal(t, redirect, r.PostForm.Get("redirect_uri"))

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.tokenStatus)
				if tc.tokenStatus != 200 {
					w.Write([]byte(`{"error":"invalid_grant"}`))
					return
				}
				idToken, _, err := server.tokenMaker.CreateIDToken("iss", "sub", []string{"42"}, time.Now().Unix(), time.Minute, tc.useNonce)
				require.NoError(t, err)
				json.NewEncoder(w).Encode(TokenPostHandlerResponse{IdToken: idToken, AccessToken: "at", TockenType: "Bearer"})
			}))
			defer fakeToken.Close()
			server.Config.TokenEndpoint = fakeToken.URL + "/token"

			b, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, "/dashboard/login", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, req)

			require.Equal(t, tc.expectCalled, called)
			require.Equal(t, tc.expectStatus, rec.Code, rec.Body.String())
			if tc.expectStatus == 200 {
				var got TokenPostHandlerResponse
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
				require.Equal(t, "at", got.AccessToken)
				require.NotEmpty(t, got.IdToken)
			}
		})
	}
}
