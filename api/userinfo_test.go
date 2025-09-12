package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mockdb "github.com/dasolerfo/hennge-one-Backend.git/db/mock"
	db "github.com/dasolerfo/hennge-one-Backend.git/db/model"
	"github.com/dasolerfo/hennge-one-Backend.git/help"
	"github.com/dasolerfo/hennge-one-Backend.git/token"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

/*
func addAuth(t *testing.T, request *http.Request, tokenMaker token.Maker, authType string, email string, duration time.Duration) {
	token, payloade, err := tokenMaker.CreateToken(email, duration)
	require.NoError(t, err)
	require.NotEmpty(t, payloade)

	authorizationHeader := fmt.Sprintf("%s %s", authType, token)
	request.Header.Set("Authorization", authorizationHeader)

}*/

func TestUserInfo(t *testing.T) {
	user := randomUser(t)

	//server := NewTestServer(t, nil)
	//issuer := "https://hennge-one.com"
	//subject := "1234567890"
	//audience := []string{"hennge-one"}
	//now := time.Now().Unix()

	//idToken, payload, err := server.tokenMaker.CreateToken(user.Email, time.Minute)

	require.NotEmpty(t, user)

	testCases := []struct {
		name          string
		createAuth    func(tokenMaker token.Maker, request *http.Request, server Server)
		buildStbus    func(store *mockdb.MockStore)
		checkResponse func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name: "OK",
			createAuth: func(tokenMaker token.Maker, request *http.Request, server Server) {
				token, payload, err := server.tokenMaker.CreateToken(user.Email, time.Minute)
				require.NoError(t, err)
				require.NotEmpty(t, token)
				require.NotEmpty(t, payload)

				fmt.Println(payload.Subject)

				authorizationHeader := fmt.Sprintf("%s %s", authType, token)
				request.Header.Set("Authorization", authorizationHeader)

			},
			buildStbus: func(store *mockdb.MockStore) {
				store.EXPECT().
					GetUserByEmail(gomock.Any(), gomock.Eq(user.Email)).
					Times(1).
					Return(user, nil)

			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, recorder.Code)
				requireBodyMatchUser(t, recorder.Body, user)
			},
		},
		{
			name: "Unathorized - No Token",
			createAuth: func(tokenMaker token.Maker, request *http.Request, server Server) {
				token, payload, err := server.tokenMaker.CreateToken(user.Email, time.Minute)
				require.NoError(t, err)
				require.NotEmpty(t, token)
				require.NotEmpty(t, payload)

				//fmt.Println(payload.Subject)

				//authorizationHeader := fmt.Sprintf("%s %s", authType, token)
				//request.Header.Set("Authorization", authorizationHeader)

			},
			buildStbus: func(store *mockdb.MockStore) {
				store.EXPECT().
					GetUserByEmail(gomock.Any(), gomock.Eq(user.Email)).
					Times(0).
					Return(user, nil)

			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
				//requireBodyMatchUser(t, recorder.Body, user)
			},
		},
		{
			name: "Invalid Token",
			createAuth: func(tokenMaker token.Maker, request *http.Request, server Server) {
				token, payload, err := server.tokenMaker.CreateToken(user.Email, time.Minute)
				require.NoError(t, err)
				require.NotEmpty(t, token)
				require.NotEmpty(t, payload)

				//fmt.Println(payload.Subject)

				authorizationHeader := fmt.Sprintf("%s %s", authType, token)
				request.Header.Set("Authorization", authorizationHeader+"invalid")

			},
			buildStbus: func(store *mockdb.MockStore) {
				store.EXPECT().
					GetUserByEmail(gomock.Any(), gomock.Eq(user.Email)).
					Times(0).
					Return(user, nil)

			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
				//requireBodyMatchUser(t, recorder.Body, user)
			},
		},
		{
			name: "Unathorized - Unknown User",
			createAuth: func(tokenMaker token.Maker, request *http.Request, server Server) {
				token, payload, err := server.tokenMaker.CreateToken("noexisteixo@gmail.com", time.Minute)
				require.NoError(t, err)
				require.NotEmpty(t, token)
				require.NotEmpty(t, payload)

				//fmt.Println(payload.Subject)

				authorizationHeader := fmt.Sprintf("%s %s", authType, token)
				request.Header.Set("Authorization", authorizationHeader)

			},
			buildStbus: func(store *mockdb.MockStore) {
				store.EXPECT().
					GetUserByEmail(gomock.Any(), gomock.Eq("noexisteixo@gmail.com")).
					Times(1).
					Return(db.User{}, sql.ErrNoRows)

			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusInternalServerError, recorder.Code)
				//requireBodyMatchUser(t, recorder.Body, user)
			},
		},
		{
			name: "Unathorized - Caducated Token",
			createAuth: func(tokenMaker token.Maker, request *http.Request, server Server) {
				token, payload, err := server.tokenMaker.CreateToken(user.Email, -time.Minute)
				require.NoError(t, err)
				require.NotEmpty(t, token)
				require.NotEmpty(t, payload)

				//fmt.Println(payload.Subject)

				authorizationHeader := fmt.Sprintf("%s %s", authType, token)
				request.Header.Set("Authorization", authorizationHeader)

			},
			buildStbus: func(store *mockdb.MockStore) {
				store.EXPECT().
					GetUserByEmail(gomock.Any(), gomock.Eq(user.Email)).
					Times(0).
					Return(db.User{}, sql.ErrNoRows)

			},
			checkResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Code)
				//requireBodyMatchUser(t, recorder.Body, user)
			},
		},
	}
	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {

			ctrl := gomock.NewController(t)

			defer ctrl.Finish()

			store := mockdb.NewMockStore(ctrl)
			tc.buildStbus(store)

			server := NewTestServer(t, store)
			recorder := httptest.NewRecorder()

			url := "/userinfo"

			request, err := http.NewRequest(http.MethodPost, url, nil)
			require.NoError(t, err)
			tc.createAuth(server.tokenMaker, request, *server)
			request.Header.Set("Content-Type", "application/json")

			server.router.ServeHTTP(recorder, request)
			tc.checkResponse(t, recorder)

		})
	}
}

func requireBodyMatchUser(t *testing.T, body *bytes.Buffer, user db.User) {
	data, err := io.ReadAll(body)
	require.NoError(t, err)

	require.NotEmpty(t, body)

	var gotUser db.User
	err = json.Unmarshal(data, &gotUser)
	require.NoError(t, err)

	require.NoError(t, err)
	fmt.Printf("User: %+v\n", gotUser.Name)
	fmt.Printf("Original User: %+v\n", user.Name)
	//require.Equal(t, user.ID, gotUser.ID)
	require.Equal(t, user.Name, gotUser.Name)
	require.Equal(t, user.Email, gotUser.Email)
	require.Equal(t, user.Gender, gotUser.Gender)
}

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
