package rest

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/todennus/oauth2-service/adapter/abstraction"
	"github.com/todennus/oauth2-service/adapter/rest/dto"
	"github.com/todennus/shared/errordef"
	"github.com/todennus/shared/middleware"
	"github.com/todennus/shared/response"
	"github.com/todennus/x/xhttp"
)

type OAuth2ClientAdapter struct {
	oauth2ClientUsecase abstraction.OAuth2ClientUsecase
}

func NewOAuth2ClientAdapter(oauth2ClientUsecase abstraction.OAuth2ClientUsecase) *OAuth2ClientAdapter {
	return &OAuth2ClientAdapter{
		oauth2ClientUsecase: oauth2ClientUsecase,
	}
}

func (a *OAuth2ClientAdapter) Router(r chi.Router) {
	r.Get("/{client_id}", middleware.RequireAuthentication(a.Get()))

	r.Post("/", middleware.RequireAuthentication(a.Create()))
	r.Post("/first", a.CreateByAdmin())
}

// @Summary Get oauth2 client by id
// @Description Get OAuth2 Client information by ClientID. <br>
// @Tags OAuth2 Client
// @Produce json
// @Param id path string true "ClientID"
// @Success 200 {object} response.SwaggerSuccessResponse[dto.OAuth2ClientGetResponse] "Get client successfully"
// @Failure 400 {object} response.SwaggerBadRequestErrorResponse "Bad request"
// @Failure 404 {object} response.SwaggerNotFoundErrorResponse "Not found"
// @Router /oauth2_clients/{client_id} [get]
func (a *OAuth2ClientAdapter) Get() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		req, err := xhttp.ParseHTTPRequest[dto.OAuth2ClientGetRequest](r)
		if err != nil {
			response.RESTWriteAndLogInvalidRequestError(ctx, w, err)
			return
		}

		resp, err := a.oauth2ClientUsecase.Get(ctx, req.To())
		response.NewRESTResponseHandler(ctx, dto.NewOAuth2ClientGetResponse(resp), err).
			Map(http.StatusBadRequest, errordef.ErrRequestInvalid).
			Map(http.StatusNotFound, errordef.ErrClientInvalid).
			WriteHTTPResponse(ctx, w)
	}
}

// @Summary Create oauth2 client
// @Description Create an new OAuth2 Client. If the `is_confidential` field is true, a secret is issued. Please carefully store this secret in a confidential place. This secret will never be retrieved by anyway. <br>
// @Description Require scope `[todennus]create:client`.
// @Tags OAuth2 Client
// @Accept json
// @Produce json
// @Param body body dto.OAuth2ClientCreateRequest true "Client Information"
// @Success 201 {object} response.SwaggerSuccessResponse[dto.OAuth2ClientCreateResponse] "Create client successfully"
// @Failure 400 {object} response.SwaggerBadRequestErrorResponse "Bad request"
// @Router /oauth2_clients [post]
func (a *OAuth2ClientAdapter) Create() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		req, err := xhttp.ParseHTTPRequest[dto.OAuth2ClientCreateRequest](r)
		if err != nil {
			response.RESTWriteAndLogInvalidRequestError(ctx, w, err)
			return
		}

		resp, err := a.oauth2ClientUsecase.Create(ctx, req.To())
		response.NewRESTResponseHandler(ctx, dto.NewOauth2ClientCreateResponse(resp), err).
			WithDefaultCode(http.StatusCreated).
			WriteHTTPResponse(ctx, w)
	}
}

// @Summary Create the first oauth2 client
// @Description Create the first OAuth2 Client (always a confidential Client). <br>
// @Description Why this API? When todennus is started, there is no existed Client, we don't have any flow to authenticate a user (all authentication flows require a Client). This API is only valid if there is no existing Client and the user is administrator.
// @Tags OAuth2 Client
// @Accept json
// @Produce json
// @Param body body dto.OAuth2ClientCreateFirstRequest true "Client Information"
// @Success 201 {object} response.SwaggerSuccessResponse[dto.OAuth2ClientCreateFirstResponse] "Create client successfully"
// @Failure 400 {object} response.SwaggerBadRequestErrorResponse "Bad request"
// @Failure 401 {object} response.SwaggerUnauthorizedErrorResponse "unauthorized"
// @Failure 403 {object} response.SwaggerForbiddenErrorResponse "Forbidden"
// @Failure 404 {object} response.SwaggerNotFoundErrorResponse "API not found"
// @Router /oauth2_clients/first [post]
func (a *OAuth2ClientAdapter) CreateByAdmin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		req, err := xhttp.ParseHTTPRequest[dto.OAuth2ClientCreateFirstRequest](r)
		if err != nil {
			response.RESTWriteAndLogInvalidRequestError(ctx, w, err)
			return
		}

		resp, err := a.oauth2ClientUsecase.CreateByAdmin(ctx, req.To())
		response.NewRESTResponseHandler(ctx, dto.NewOauth2ClientCreateFirstResponse(resp), err).
			Map(http.StatusForbidden, errordef.ErrForbidden).
			Map(http.StatusNotFound, errordef.ErrNotFound).
			Map(http.StatusUnauthorized, errordef.ErrUnauthenticated).
			WithDefaultCode(http.StatusCreated).
			WriteHTTPResponse(ctx, w)
	}
}
