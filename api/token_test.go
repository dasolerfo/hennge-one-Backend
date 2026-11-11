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

// PKCE example from RFC 7636 Appendix B.
const (
	testCodeVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestTokenPostHandler_TableDriven(t *testing.T) {
	user := randomUser(t)
	const redirectURI = "http://localhost/cb"

	// Confidential client using client_secret_post (the default for existing clients).
	client := db.Client{
		ID:                      123,
		ClientSecret:            "secret",
		ClientType:              ClientTypeConfidential,
		TokenEndpointAuthMethod: AuthMethodClientSecretPost,
		GrantTypes:              []string{GrantTypeAuthorizationCode},
	}
	basicClient := client
	basicClient.TokenEndpointAuthMethod = AuthMethodClientSecretBasic

	pkceClient := client
	pkceClient.RequirePkce = true

	publicClient := db.Client{
		ID:                      456,
		ClientType:              ClientTypePublic,
		TokenEndpointAuthMethod: AuthMethodNone,
		GrantTypes:              []string{GrantTypeAuthorizationCode},
		RequirePkce:             true,
	}

	authCode := db.AuthCode{
		Code:        "validcode",
		Used:        false,
		ClientID:    client.ID,
		RedirectUri: redirectURI,
		Scope:       sql.NullString{String: "openid", Valid: true},
		Sub:         user.Sub.String(),
		CreatedAt:   time.Now(),
	}
	pkceCode := authCode
	pkceCode.CodeChallenge = sql.NullString{String: testCodeChallenge, Valid: true}
	pkceCode.CodeChallengeMethod = sql.NullString{String: PKCEMethodS256, Valid: true}
	publicCode := pkceCode
	publicCode.ClientID = publicClient.ID

	// form builds a token request; extra entries override or add fields
	// (an empty value removes the field).
	form := func(clientID int64, extra map[string]string) url.Values {
		v := url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {fmt.Sprintf("%d", clientID)},
			"client_secret": {"secret"},
			"redirect_uri":  {url.QueryEscape(redirectURI)},
			"code":          {"validcode"},
		}
		for k, val := range extra {
			if val == "" {
				v.Del(k)
			} else {
				v.Set(k, val)
			}
		}
		return v
	}

	// happyPath stubs a full successful exchange for the given client and code.
	happyPath := func(store *mockdb.MockStore, cl db.Client, code db.AuthCode) {
		store.EXPECT().GetClientByID(gomock.Any(), cl.ID).Times(1).Return(cl, nil)
		store.EXPECT().GetAuthCode(gomock.Any(), code.Code).Times(1).Return(code, nil)
		store.EXPECT().SetCodeUsed(gomock.Any(), code.Code).Times(1).Return(nil)
		store.EXPECT().GetUserBySub(gomock.Any(), user.Sub).Times(1).Return(user, nil)
	}
	requireOK := func(t *testing.T, recorder *httptest.ResponseRecorder) {
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
		require.Contains(t, recorder.Body.String(), "id_token")
		require.Contains(t, recorder.Body.String(), "access_token")
	}
	requireError := func(status int, errCode, desc string) func(t *testing.T, recorder *httptest.ResponseRecorder) {
		return func(t *testing.T, recorder *httptest.ResponseRecorder) {
			require.Equal(t, status, recorder.Code, recorder.Body.String())
			require.Contains(t, recorder.Body.String(), errCode)
			require.Contains(t, recorder.Body.String(), desc)
		}
	}

	testCases := []struct {
		name          string
		buildStubs    func(store *mockdb.MockStore)
		form          url.Values
		basicAuth     []string // {client_id, secret} sent as HTTP Basic
		checkResponse func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name:          "OK",
			buildStubs:    func(store *mockdb.MockStore) { happyPath(store, client, authCode) },
			form:          form(client.ID, nil),
			checkResponse: requireOK,
		},
		{
			name:          "InvalidGrantType",
			buildStubs:    func(store *mockdb.MockStore) {},
			form:          form(client.ID, map[string]string{"grant_type": "password"}),
			checkResponse: requireError(http.StatusBadRequest, "unsupported_grant_type", ""),
		},
		{
			name: "UsedCode",
			buildStubs: func(store *mockdb.MockStore) {
				usedCode := authCode
				usedCode.Used = true
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(client, nil)
				store.EXPECT().GetAuthCode(gomock.Any(), "validcode").Times(1).Return(usedCode, nil)
			},
			form:          form(client.ID, nil),
			checkResponse: requireError(http.StatusBadRequest, "invalid_grant", "already been used"),
		},
		{
			name: "ClientIDMismatch",
			buildStubs: func(store *mockdb.MockStore) {
				mismatchCode := authCode
				mismatchCode.ClientID = 999
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(client, nil)
				store.EXPECT().GetAuthCode(gomock.Any(), "validcode").Times(1).Return(mismatchCode, nil)
			},
			form:          form(client.ID, nil),
			checkResponse: requireError(http.StatusBadRequest, "invalid_grant", "client ID does not match"),
		},
		{
			name: "InvalidClient",
			buildStubs: func(store *mockdb.MockStore) {
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(db.Client{}, errors.New("not found"))
			},
			form:          form(client.ID, nil),
			checkResponse: requireError(http.StatusBadRequest, "invalid_client", ""),
		},
		{
			name: "InvalidClientSecret",
			buildStubs: func(store *mockdb.MockStore) {
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(client, nil)
			},
			form:          form(client.ID, map[string]string{"client_secret": "othersecret"}),
			checkResponse: requireError(http.StatusBadRequest, "invalid_client", "client secret is invalid"),
		},
		{
			name: "MissingSecretForConfidentialClient",
			buildStubs: func(store *mockdb.MockStore) {
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(client, nil)
			},
			form:          form(client.ID, map[string]string{"client_secret": ""}),
			checkResponse: requireError(http.StatusBadRequest, "invalid_client", "client_secret_post"),
		},
		{
			name: "InvalidRedirectURI",
			buildStubs: func(store *mockdb.MockStore) {
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(client, nil)
				store.EXPECT().GetAuthCode(gomock.Any(), "validcode").Times(1).Return(authCode, nil)
			},
			form:          form(client.ID, map[string]string{"redirect_uri": "%"}),
			checkResponse: requireError(http.StatusBadRequest, "invalid_request", "redirect URI is not valid"),
		},
		{
			name: "RedirectURIMismatch",
			buildStubs: func(store *mockdb.MockStore) {
				mismatchCode := authCode
				mismatchCode.RedirectUri = "http://localhost/other"
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(client, nil)
				store.EXPECT().GetAuthCode(gomock.Any(), "validcode").Times(1).Return(mismatchCode, nil)
			},
			form:          form(client.ID, nil),
			checkResponse: requireError(http.StatusBadRequest, "invalid_grant", "redirect URI does not match"),
		},
		{
			name: "InvalidScope",
			buildStubs: func(store *mockdb.MockStore) {
				badScopeCode := authCode
				badScopeCode.Scope.String = "profile"
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(client, nil)
				store.EXPECT().GetAuthCode(gomock.Any(), "validcode").Times(1).Return(badScopeCode, nil)
			},
			form:          form(client.ID, nil),
			checkResponse: requireError(http.StatusBadRequest, "invalid_scope", ""),
		},
		{
			name: "SetCodeUsedError",
			buildStubs: func(store *mockdb.MockStore) {
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(client, nil)
				store.EXPECT().GetAuthCode(gomock.Any(), "validcode").Times(1).Return(authCode, nil)
				store.EXPECT().SetCodeUsed(gomock.Any(), "validcode").Times(1).Return(errors.New("db error"))
			},
			form:          form(client.ID, nil),
			checkResponse: requireError(http.StatusInternalServerError, "server_error", ""),
		},
		{
			name: "GetUserBySubError",
			buildStubs: func(store *mockdb.MockStore) {
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(client, nil)
				store.EXPECT().GetAuthCode(gomock.Any(), "validcode").Times(1).Return(authCode, nil)
				store.EXPECT().SetCodeUsed(gomock.Any(), "validcode").Times(1).Return(nil)
				store.EXPECT().GetUserBySub(gomock.Any(), user.Sub).Times(1).Return(db.User{}, errors.New("not found"))
			},
			form:          form(client.ID, nil),
			checkResponse: requireError(http.StatusInternalServerError, "server_error", ""),
		},
		{
			name:          "MissingFields",
			buildStubs:    func(store *mockdb.MockStore) {},
			form:          url.Values{},
			checkResponse: requireError(http.StatusBadRequest, "invalid_request", ""),
		},
		{
			name:          "MissingClientID",
			buildStubs:    func(store *mockdb.MockStore) {},
			form:          form(client.ID, map[string]string{"client_id": "", "client_secret": ""}),
			checkResponse: requireError(http.StatusBadRequest, "invalid_request", "client_id is required"),
		},

		// --- Client authentication methods ---
		{
			name:          "BasicAuthOK",
			buildStubs:    func(store *mockdb.MockStore) { happyPath(store, basicClient, authCode) },
			form:          form(client.ID, map[string]string{"client_id": "", "client_secret": ""}),
			basicAuth:     []string{"123", "secret"},
			checkResponse: requireOK,
		},
		{
			name: "BasicAuthWrongSecret",
			buildStubs: func(store *mockdb.MockStore) {
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(basicClient, nil)
			},
			form:      form(client.ID, map[string]string{"client_id": "", "client_secret": ""}),
			basicAuth: []string{"123", "wrong"},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				requireError(http.StatusUnauthorized, "invalid_client", "client secret is invalid")(t, recorder)
				require.NotEmpty(t, recorder.Header().Get("WWW-Authenticate"))
			},
		},
		{
			name: "PostUsedButClientRegisteredBasic",
			buildStubs: func(store *mockdb.MockStore) {
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(basicClient, nil)
			},
			form:          form(client.ID, nil),
			checkResponse: requireError(http.StatusBadRequest, "invalid_client", "client_secret_basic"),
		},
		{
			name:          "BasicAndPostTogether",
			buildStubs:    func(store *mockdb.MockStore) {},
			form:          form(client.ID, nil),
			basicAuth:     []string{"123", "secret"},
			checkResponse: requireError(http.StatusBadRequest, "invalid_request", "multiple client authentication"),
		},
		{
			name: "GrantTypeNotAllowedForClient",
			buildStubs: func(store *mockdb.MockStore) {
				restricted := client
				restricted.GrantTypes = []string{"client_credentials"}
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(restricted, nil)
			},
			form:          form(client.ID, nil),
			checkResponse: requireError(http.StatusBadRequest, "unauthorized_client", ""),
		},

		// --- PKCE ---
		{
			name:          "PublicClientPKCEOK",
			buildStubs:    func(store *mockdb.MockStore) { happyPath(store, publicClient, publicCode) },
			form:          form(publicClient.ID, map[string]string{"client_secret": "", "code_verifier": testCodeVerifier}),
			checkResponse: requireOK,
		},
		{
			name: "PublicClientWithSecret",
			buildStubs: func(store *mockdb.MockStore) {
				store.EXPECT().GetClientByID(gomock.Any(), publicClient.ID).Times(1).Return(publicClient, nil)
			},
			form:          form(publicClient.ID, map[string]string{"code_verifier": testCodeVerifier}),
			checkResponse: requireError(http.StatusBadRequest, "invalid_client", "must authenticate with none"),
		},
		{
			name: "MissingCodeVerifier",
			buildStubs: func(store *mockdb.MockStore) {
				store.EXPECT().GetClientByID(gomock.Any(), publicClient.ID).Times(1).Return(publicClient, nil)
				store.EXPECT().GetAuthCode(gomock.Any(), "validcode").Times(1).Return(publicCode, nil)
			},
			form:          form(publicClient.ID, map[string]string{"client_secret": ""}),
			checkResponse: requireError(http.StatusBadRequest, "invalid_grant", "code_verifier is required"),
		},
		{
			name: "WrongCodeVerifier",
			buildStubs: func(store *mockdb.MockStore) {
				store.EXPECT().GetClientByID(gomock.Any(), publicClient.ID).Times(1).Return(publicClient, nil)
				store.EXPECT().GetAuthCode(gomock.Any(), "validcode").Times(1).Return(publicCode, nil)
			},
			form:          form(publicClient.ID, map[string]string{"client_secret": "", "code_verifier": strings.Repeat("a", 43)}),
			checkResponse: requireError(http.StatusBadRequest, "invalid_grant", "does not match the code_challenge"),
		},
		{
			name:          "ConfidentialClientWithPKCEOK",
			buildStubs:    func(store *mockdb.MockStore) { happyPath(store, client, pkceCode) },
			form:          form(client.ID, map[string]string{"code_verifier": testCodeVerifier}),
			checkResponse: requireOK,
		},
		{
			name: "VerifierWithoutChallenge",
			buildStubs: func(store *mockdb.MockStore) {
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(client, nil)
				store.EXPECT().GetAuthCode(gomock.Any(), "validcode").Times(1).Return(authCode, nil)
			},
			form:          form(client.ID, map[string]string{"code_verifier": testCodeVerifier}),
			checkResponse: requireError(http.StatusBadRequest, "invalid_grant", "had no code_challenge"),
		},
		{
			name: "ClientRequiresPKCEButCodeHasNone",
			buildStubs: func(store *mockdb.MockStore) {
				store.EXPECT().GetClientByID(gomock.Any(), client.ID).Times(1).Return(pkceClient, nil)
				store.EXPECT().GetAuthCode(gomock.Any(), "validcode").Times(1).Return(authCode, nil)
			},
			form:          form(client.ID, nil),
			checkResponse: requireError(http.StatusBadRequest, "invalid_grant", "requires PKCE"),
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

			tc.buildStubs(store)

			server := NewTestServerWithTokenMaker(t, store, tokenMaker)
			recorder := httptest.NewRecorder()
			req, err := http.NewRequest(http.MethodPost, "/token", strings.NewReader(tc.form.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.basicAuth != nil {
				req.SetBasicAuth(url.QueryEscape(tc.basicAuth[0]), url.QueryEscape(tc.basicAuth[1]))
			}
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
