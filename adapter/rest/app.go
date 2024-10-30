package rest

import (
	"net/http"

	"github.com/todennus/shared/middleware"

	"github.com/go-chi/chi/v5"
	"github.com/todennus/oauth2-service/wiring"
	"github.com/todennus/shared/config"
)

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

	oauth2FlowAdapter := NewOAuth2Adapter(usecases.OAuth2FlowUsecase, usecases.OAuth2ConsentUsecase)
	authenticationAdapter := NewAuthenticationAdapter(usecases.OAuth2AuthenticationUsecase)

	r.Route("/auth", authenticationAdapter.Router)
	r.Route("/oauth2", oauth2FlowAdapter.Router)

	r.NotFound(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })

	return r
}
