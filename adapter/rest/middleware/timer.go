package middleware

import (
	"net/http"
	"time"

	"github.com/todennus/config"
	"github.com/todennus/x/xcontext"
)

func Timer(config *config.Config) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			xcontext.Logger(ctx).Debug("request",
				"uri", r.RequestURI,
				"method", r.Method,
				"rip", r.RemoteAddr,
				"node_id", config.Variable.Server.NodeID,
			)

			start := time.Now()
			next.ServeHTTP(w, r)

			xcontext.Logger(ctx).Debug("response", "rtt", time.Since(start))
		})
	}
}
