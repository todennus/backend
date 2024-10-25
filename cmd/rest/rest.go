package rest

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/todennus/oauth2-service/adapter/rest"
	"github.com/todennus/oauth2-service/wiring"
)

var Command = &cobra.Command{
	Use:   "rest",
	Short: "Start the REST API server",
	Run: func(cmd *cobra.Command, args []string) {
		envPaths, err := cmd.Flags().GetStringArray("env")
		if err != nil {
			panic(err)
		}

		system, err := wiring.InitializeSystem(envPaths...)
		if err != nil {
			panic(err)
		}

		address := fmt.Sprintf("%s:%d", system.Config.Variable.Server.Host, system.Config.Variable.Server.Port)
		app := rest.App(system.Config, system.Usecases)

		slog.Info("Server started", "address", address)
		if err := http.ListenAndServe(address, app); err != nil {
			panic(err)
		}
	},
}
