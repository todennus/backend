package wiring

import (
	"context"
	"fmt"

	"github.com/todennus/shared/config"
)

type System struct {
	Config       *config.Config
	Domains      *Domains
	Infras       *Infras
	Repositories *Repositories
	Usecases     *Usecases
}

func InitializeSystem(paths ...string) (*System, error) {
	config, err := config.Load(sources(paths)...)
	if err != nil {
		return nil, fmt.Errorf("failed to load variable and secrets, err=%w", err)
	}

	ctx := context.Background()
	domains, err := InitializeDomains(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize domains, err=%w", err)
	}

	infras, err := InitializeInfras(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize infras, err=%w", err)
	}

	repositories, err := InitializeRepositories(ctx, config, infras)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize repositories, err=%w", err)
	}

	usecases, err := InitializeUsecases(ctx, config, infras, domains, repositories)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize usecases, err=%w", err)
	}

	return &System{
		Config:       config,
		Infras:       infras,
		Repositories: repositories,
		Domains:      domains,
		Usecases:     usecases,
	}, nil
}

func sources(paths []string) []string {
	sources := []string{}
	for i := range paths {
		if len(paths[i]) > 0 {
			sources = append(sources, paths[i])
		}
	}

	return sources
}
