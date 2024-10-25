package rest

import (
	"net/http"

	"github.com/todennus/shared/middleware"

	"github.com/go-chi/chi/v5"
	"github.com/todennus/oauth2-service/wiring"
	"github.com/todennus/shared/config"
)

// @title Todennus API Endpoints
// @version 1.0
// @description This is Todennus - An Open ID Connect and OAuth2 Provider
func App(
	config *config.Config,
	usecases *wiring.Usecases,
) chi.Router {
	r := chi.NewRouter()

	r.Use(middleware.SetupContext(config))
	r.Use(middleware.Recoverer())
	r.Use(middleware.LogRequest(config))
	r.Use(middleware.Timeout(config))
	r.Use(middleware.Authentication(config.TokenEngine))
	r.Use(middleware.WithSession(config.SessionManager))

	oauth2FlowAdapter := NewOAuth2Adapter(usecases.OAuth2Usecase)
	oauth2ClientAdapter := NewOAuth2ClientAdapter(usecases.OAuth2ClientUsecase)

	r.Get("/session/update", oauth2FlowAdapter.SessionUpdate())
	r.Post("/auth/callback", oauth2FlowAdapter.AuthenticationCallback())

	r.Route("/oauth2", oauth2FlowAdapter.OAuth2Router)
	r.Route("/oauth2_clients", oauth2ClientAdapter.Router)

	r.NotFound(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })

	return r
}
