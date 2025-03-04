package cmd

import (
	"os"
	"radar/internal/log"
	"radar/pkg/elasticsearch"

	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "radar",
	Short: "Radar is a tool to scan the web for vulnerabilities.",
	Long:  "Radar is a tool to scan the web for vulnerabilities.",
	Run: func(cmd *cobra.Command, args []string) {
		log.Warning("Use --help to see available commands")
	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().BoolVarP(&log.Verbose, "verbose", "v", false, "verbose error messages")
	RootCmd.PersistentFlags().StringVarP(&elasticsearch.Url, "elastic-url", "", "http://localhost:9200", "elasticsearch url")
	RootCmd.PersistentFlags().BoolVarP(&elasticsearch.Auth, "elastic-auth", "", false, "elasticsearch auth enabled")
	RootCmd.PersistentFlags().StringVarP(&elasticsearch.Username, "elastic-username", "", "", "elasticsearch username")
	RootCmd.PersistentFlags().StringVarP(&elasticsearch.Password, "elastic-password", "", "", "elasticsearch password")
}
