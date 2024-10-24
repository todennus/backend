package middleware

import (
	"net/http"

	"github.com/todennus/backend/adapter/common"
	"github.com/todennus/backend/adapter/rest/response"
	"github.com/todennus/backend/adapter/rest/standard"
	"github.com/todennus/x/token"
	"github.com/todennus/x/xcontext"
)

func Authentication(engine token.Engine) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			authorization := r.Header.Get("Authorization")

			next.ServeHTTP(w, r.WithContext(common.WithAuthenticate(ctx, authorization, engine)))
		})
	}
}

func RequireAuthentication(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if xcontext.RequestUserID(ctx) == 0 {
			response.Write(ctx, w, http.StatusUnauthorized,
				standard.NewErrorResponseWithMessage(ctx, "unauthenticated", "require authentication to access api"))
		} else {
			handler(w, r)
		}
	}
}
