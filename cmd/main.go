package main

import (
	"github.com/spf13/cobra"
	"github.com/todennus/oauth2-service/cmd/rest"
)

var rootCommand = &cobra.Command{
	Use:   "todennus",
	Short: "todennus is an Identity, OpenID Connect, and OAuth2 provider",
}

func main() {
	rootCommand.PersistentFlags().StringArray("env", []string{".env"}, "environment file paths")
	rootCommand.AddCommand(rest.Command)

	if err := rootCommand.Execute(); err != nil {
		panic(err)
	}
}
