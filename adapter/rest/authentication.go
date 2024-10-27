package rest

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/todennus/oauth2-service/adapter/abstraction"
	"github.com/todennus/oauth2-service/adapter/rest/dto"
	"github.com/todennus/shared/errordef"
	"github.com/todennus/shared/response"
	"github.com/todennus/x/xhttp"
)

type AuthenticationAdapter struct {
	oauth2AuthencationUsecase abstraction.OAuth2AuthenticationUsecase
}

func NewAuthenticationAdapter(
	oauth2AuthencationUsecase abstraction.OAuth2AuthenticationUsecase,
) *AuthenticationAdapter {
	return &AuthenticationAdapter{oauth2AuthencationUsecase: oauth2AuthencationUsecase}
}

func (a *AuthenticationAdapter) Router(r chi.Router) {
	r.Post("/callback", a.AuthenticationCallback())
	r.Get("/update", a.SessionUpdate())
}

// @Summary Authentication Callback Endpoint
// @Description This endpoint is called by the IdP after it validated the user.
// @Description It notifies to the server about the authentication result (success or failure) and the information of user.
// @Tags OAuth2
// @Accept json
// @Produce json
// @Param body body dto.OAuth2AuthenticationCallbackRequest true "Authentication result"
// @Success 200 {object} dto.OAuth2AuthenticationCallbackResponse "Successfully accept the result"
// @Failure 400 {object} response.SwaggerBadRequestErrorResponse "Bad request"
// @Failure 403 {object} response.SwaggerForbiddenErrorResponse "Forbidden"
// @Failure 404 {object} response.SwaggerNotFoundErrorResponse "Not found"
// @Router /auth/callback [post]
func (a *AuthenticationAdapter) AuthenticationCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		req, err := xhttp.ParseHTTPRequest[dto.OAuth2AuthenticationCallbackRequest](r)
		if err != nil {
			response.RESTWriteAndLogInvalidRequestError(ctx, w, err)
			return
		}

		usecaseReq, err := req.To()
		if err != nil {
			response.RESTWriteAndLogInvalidRequestError(ctx, w, err)
			return
		}

		resp, err := a.oauth2AuthencationUsecase.AuthenticationCallback(ctx, usecaseReq)
		response.NewRESTResponseHandler(ctx, dto.NewOAuth2AuthenticationCallbackResponse(resp), err).
			Map(http.StatusBadRequest, errordef.ErrRequestInvalid).
			Map(http.StatusNotFound, errordef.ErrNotFound).
			Map(http.StatusForbidden, errordef.ErrCredentialsInvalid).
			WriteHTTPResponse(ctx, w)
	}
}

// @Summary Authentication Update Endpoint
// @Description The IdP redirects the user to this endpoint after it sends the authentication result to the server. <br>
// @Description This endpoint updates the user session state to `authenticated`, `unauthenticated`, or `failed authentication`.
// @Tags OAuth2
// @Param authentication_id query string true "Authentication id"
// @Success 303 "Redirect back to oauth2 authorization endpoint"
// @Failure 400 {object} response.SwaggerBadRequestErrorResponse "Bad request"
// @Router /auth/update [get]
func (a *AuthenticationAdapter) SessionUpdate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		req, err := xhttp.ParseHTTPRequest[dto.OAuth2SessionUpdateRequest](r)
		if err != nil {
			response.RESTWriteAndLogInvalidRequestError(ctx, w, err)
			return
		}

		resp, err := a.oauth2AuthencationUsecase.SessionUpdate(ctx, req.To())
		response.NewRESTResponseHandler(ctx, dto.NewOAuth2SessionUpdateRedirectURI(resp), err).
			Map(http.StatusBadRequest, errordef.ErrRequestInvalid).
			Redirect(ctx, w, r, http.StatusSeeOther)
	}
}
