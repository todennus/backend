package middleware

import (
	"net/http"

	"github.com/todennus/x/xcontext"
	"github.com/todennus/x/xcrypto"
)

func WithRequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = xcontext.WithRequestID(ctx, xcrypto.RandString(16))

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
