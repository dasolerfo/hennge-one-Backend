package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	mockdb "github.com/dasolerfo/hennge-one-Backend.git/db/mock"
	db "github.com/dasolerfo/hennge-one-Backend.git/db/model"
	"github.com/dasolerfo/hennge-one-Backend.git/token"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestTokenPostHandler_TableDriven(t *testing.T) {
	user := randomUser(t)
	client := db.Client{
		ID:           123,
		ClientSecret: "secret",
	}
	authCode := db.AuthCode{
		Code:        "validcode",
		Used:        false,
		ClientID:    client.ID,
		RedirectUri: "http://localhost/cb",
		Scope:       sql.NullString{String: "openid", Valid: true},
		Sub:         fmt.Sprintf("%d", user.ID),
		CreatedAt:   time.Now(),
	}
	//payload := &token.Payload{ExpiredAt: 3600}

	testCases := []struct {
		name          string
		buildStubs    func(store *mockdb.MockStore, tokenMaker *token.JWTMaker)
		form          url.Values
		checkResponse func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name: "OK",
			buildStubs: func(store *mockdb.MockStore, tokenMaker *token.JWTMaker) {
				store.EXPECT().GetAuthCode(gomock.Any(), "validcode").Times(1).Return(authCode, nil)
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(client, nil)
				store.EXPECT().SetCodeUsed(gomock.Any(), "validcode").Times(1).Return(nil)
				store.EXPECT().GetUserByID(gomock.Any(), user.ID).Times(1).Return(user, nil)
				//tokenMaker.CreateIDToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return("idtoken", payload, nil)
				//tokenMaker.CreateToken(user.Email, gomock.Any()).Times(1).Return("accesstoken", payload, nil)
			},
			form: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {fmt.Sprintf("%d", client.ID)},
				"client_secret": {client.ClientSecret},
				"redirect_uri":  {url.QueryEscape(authCode.RedirectUri)},
				"code":          {authCode.Code},
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, recorder.Code)
				require.Contains(t, recorder.Body.String(), "id_token")
				require.Contains(t, recorder.Body.String(), "access_token")
			},
		},
		{
			name:       "InvalidGrantType",
			buildStubs: func(store *mockdb.MockStore, tokenMaker *token.JWTMaker) {},
			form: url.Values{
				"grant_type":    {"invalid"},
				"client_id":     {"123"},
				"client_secret": {"secret"},
				"redirect_uri":  {url.QueryEscape("http://localhost/cb")},
				"code":          {"validcode"},
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusBadRequest, recorder.Code)
				require.Contains(t, recorder.Body.String(), "invalid_request")
			},
		},
		{
			name: "UsedCode",
			buildStubs: func(store *mockdb.MockStore, tokenMaker *token.JWTMaker) {
				usedCode := authCode
				usedCode.Used = true
				store.EXPECT().GetAuthCode(gomock.Any(), "usedcode").Times(1).Return(usedCode, nil)
			},
			form: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"123"},
				"client_secret": {"secret"},
				"redirect_uri":  {url.QueryEscape("http://localhost/cb")},
				"code":          {"usedcode"},
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusBadRequest, recorder.Code)
				require.Contains(t, recorder.Body.String(), "already been used")
			},
		},
		{
			name: "ClientIDMismatch",
			buildStubs: func(store *mockdb.MockStore, tokenMaker *token.JWTMaker) {
				mismatchCode := authCode
				mismatchCode.ClientID = 999
				store.EXPECT().GetAuthCode(gomock.Any(), "code").Times(1).Return(mismatchCode, nil)
			},
			form: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"123"},
				"client_secret": {"secret"},
				"redirect_uri":  {url.QueryEscape("http://localhost/cb")},
				"code":          {"code"},
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusBadRequest, recorder.Code)
				require.Contains(t, recorder.Body.String(), "client ID does not match")
			},
		},
		{
			name: "InvalidClient",
			buildStubs: func(store *mockdb.MockStore, tokenMaker *token.JWTMaker) {
				store.EXPECT().GetAuthCode(gomock.Any(), "code").Times(1).Return(&authCode, nil)
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(nil, errors.New("not found"))
			},
			form: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"123"},
				"client_secret": {"secret"},
				"redirect_uri":  {url.QueryEscape("http://localhost/cb")},
				"code":          {"code"},
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusBadRequest, recorder.Code)
				require.Contains(t, recorder.Body.String(), "invalid_client")
			},
		},
		{
			name: "InvalidClientSecret",
			buildStubs: func(store *mockdb.MockStore, tokenMaker *token.JWTMaker) {
				badSecretClient := client
				badSecretClient.ClientSecret = "othersecret"
				store.EXPECT().GetAuthCode(gomock.Any(), "code").Times(1).Return(&authCode, nil)
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(&badSecretClient, nil)
			},
			form: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"123"},
				"client_secret": {"secret"},
				"redirect_uri":  {url.QueryEscape("http://localhost/cb")},
				"code":          {"code"},
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusBadRequest, recorder.Code)
				require.Contains(t, recorder.Body.String(), "client secret is invalid")
			},
		},
		{
			name: "InvalidRedirectURI",
			buildStubs: func(store *mockdb.MockStore, tokenMaker *token.JWTMaker) {
				store.EXPECT().GetAuthCode(gomock.Any(), "code").Times(1).Return(&authCode, nil)
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(&client, nil)
			},
			form: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"123"},
				"client_secret": {"secret"},
				"redirect_uri":  {"%"},
				"code":          {"code"},
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusBadRequest, recorder.Code)
				require.Contains(t, recorder.Body.String(), "redirect URI is not valid")
			},
		},
		{
			name: "RedirectURIMismatch",
			buildStubs: func(store *mockdb.MockStore, tokenMaker *token.JWTMaker) {
				mismatchCode := authCode
				mismatchCode.RedirectUri = "http://localhost/other"
				store.EXPECT().GetAuthCode(gomock.Any(), "code").Times(1).Return(&mismatchCode, nil)
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(&client, nil)
			},
			form: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"123"},
				"client_secret": {"secret"},
				"redirect_uri":  {url.QueryEscape("http://localhost/cb")},
				"code":          {"code"},
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusBadRequest, recorder.Code)
				require.Contains(t, recorder.Body.String(), "redirect URI does not match")
			},
		},
		{
			name: "InvalidScope",
			buildStubs: func(store *mockdb.MockStore, tokenMaker *token.JWTMaker) {
				badScopeCode := authCode
				badScopeCode.Scope.String = "profile"
				store.EXPECT().GetAuthCode(gomock.Any(), "code").Times(1).Return(&badScopeCode, nil)
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(&client, nil)
			},
			form: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"123"},
				"client_secret": {"secret"},
				"redirect_uri":  {url.QueryEscape("http://localhost/cb")},
				"code":          {"code"},
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusBadRequest, recorder.Code)
				require.Contains(t, recorder.Body.String(), "scope is not valid")
			},
		},
		{
			name: "SetCodeUsedError",
			buildStubs: func(store *mockdb.MockStore, tokenMaker *token.JWTMaker) {
				store.EXPECT().GetAuthCode(gomock.Any(), "validcode").Times(1).Return(&authCode, nil)
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(&client, nil)
				store.EXPECT().SetCodeUsed(gomock.Any(), "validcode").Times(1).Return(errors.New("db error"))
				store.EXPECT().GetUserByID(gomock.Any(), user.ID).Times(1).Return(&user, nil)
				//tokenMaker.EXPECT().CreateIDToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return("idtoken", payload, nil)
				//tokenMaker.EXPECT().CreateToken(user.Email, gomock.Any()).Times(1).Return("accesstoken", payload, nil)
			},
			form: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"123"},
				"client_secret": {"secret"},
				"redirect_uri":  {url.QueryEscape("http://localhost/cb")},
				"code":          {"validcode"},
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusInternalServerError, recorder.Code)
				require.Contains(t, recorder.Body.String(), "server_error")
			},
		},
		{
			name: "GetUserByIDError",
			buildStubs: func(store *mockdb.MockStore, tokenMaker *token.JWTMaker) {
				store.EXPECT().GetAuthCode(gomock.Any(), "validcode").Times(1).Return(&authCode, nil)
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(&client, nil)
				store.EXPECT().SetCodeUsed(gomock.Any(), "validcode").Times(1).Return(nil)
				store.EXPECT().GetUserByID(gomock.Any(), user.ID).Times(1).Return(nil, errors.New("not found"))
				//tokenMaker.EXPECT().CreateIDToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return("idtoken", payload, nil)
				//tokenMaker.EXPECT().CreateToken(gomock.Any(), gomock.Any()).Times(1).Return("accesstoken", payload, nil)
			},
			form: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"123"},
				"client_secret": {"secret"},
				"redirect_uri":  {url.QueryEscape("http://localhost/cb")},
				"code":          {"validcode"},
			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusInternalServerError, recorder.Code)
				require.Contains(t, recorder.Body.String(), "server_error")
			},
		},
		{
			name:       "MissingFields",
			buildStubs: func(store *mockdb.MockStore, tokenMaker *token.JWTMaker) {},
			form:       url.Values{},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusBadRequest, recorder.Code)
				require.Contains(t, recorder.Body.String(), "invalid_request")
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			store := mockdb.NewMockStore(ctrl)

			tokenMaker, err := token.NewJWTMaker(2048)
			require.NoError(t, err)

			tc.buildStubs(store, tokenMaker)

			server := NewTestServerWithTokenMaker(t, store, tokenMaker)
			recorder := httptest.NewRecorder()
			req, err := http.NewRequest(http.MethodPost, "/token", strings.NewReader(tc.form.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			server.router.ServeHTTP(recorder, req)
			tc.checkResponse(t, recorder)
		})
	}
}

// Helper for test server with custom tokenMaker
func NewTestServerWithTokenMaker(t *testing.T, store db.Store, tokenMaker token.Maker) *Server {
	server := NewTestServer(t, store)
	server.tokenMaker = tokenMaker
	return server
}

// Helper for random user
/*
func randomUser(t *testing.T) db.User {
	password := help.RandomString(10)
	hashedPassword, err := help.HashPassword(password)
	require.NoError(t, err)
	require.NotEmpty(t, hashedPassword)
	return db.User{
		ID:             help.RandomInt(1, 1000),
		Name:           help.RandomString(9),
		Email:          help.RandomEmail(),
		EmailVerified:  true,
		HashedPassword: hashedPassword,
		Gender:         sql.NullString{String: "male", Valid: true},
		CreatedAt:      time.Now(),
	}
}
*/
// Helper for matching response
func requireBodyMatchTokenResponse(t *testing.T, body *bytes.Buffer, want map[string]interface{}) {
	data, err := io.ReadAll(body)
	require.NoError(t, err)
	var got map[string]interface{}
	err = json.Unmarshal(data, &got)
	require.NoError(t, err)
	for k, v := range want {
		require.Equal(t, v, got[k])
	}
}
