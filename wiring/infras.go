package wiring

import (
	"context"
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"
	"github.com/todennus/migration/postgres"
	infrasgrpc "github.com/todennus/oauth2-service/infras/service/grpc"
	"github.com/todennus/shared/authentication"
	"github.com/todennus/shared/config"
	"github.com/todennus/shared/scopedef"
	"github.com/xybor-x/snowflake"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gorm.io/gorm"
)

type Infras struct {
	Auth                 *authentication.GrpcAuthorization
	GormPostgres         *gorm.DB
	Redis                *redis.Client
	UsergRPCConn         *grpc.ClientConn
	OAuth2ClientgRPCConn *grpc.ClientConn
}

func InitializeInfras(ctx context.Context, config *config.Config, domains *Domains) (*Infras, error) {
	infras := Infras{}
	var err error

	infras.GormPostgres, err = postgres.Initialize(ctx, config)
	if err != nil {
		return nil, err
	}

	infras.Redis = redis.NewClient(&redis.Options{
		Addr:     config.Variable.Redis.Addr,
		DB:       config.Variable.Redis.DB,
		Username: config.Secret.Redis.Username,
		Password: config.Secret.Redis.Password,
	})

	infras.UsergRPCConn, err = grpc.NewClient(
		config.Variable.Service.UserGRPCAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	infras.OAuth2ClientgRPCConn, err = grpc.NewClient(
		config.Variable.Service.OAuth2ClientGRPCAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	clientID, err := snowflake.ParseString(config.Secret.Service.ClientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client id: %w", err)
	}

	scopes := []string{
		scopedef.AdminReadUserProfile.Scope(),
		scopedef.AdminValidateUser.Scope(),
		scopedef.AdminReadClientProfile.Scope(),
		scopedef.AdminValidateClient.Scope(),
	}
	scopesStr := scopedef.Engine.ParseDefinedScopes(strings.Join(scopes, " "))

	infras.Auth = authentication.NewGrpcAuthorization(func(ctx context.Context) oauth2.TokenSource {
		return infrasgrpc.NewSelfAuthTokenSource(
			ctx, clientID, scopesStr, config.TokenEngine, domains.OAuth2TokenDomain)
	})

	return &infras, nil
}
