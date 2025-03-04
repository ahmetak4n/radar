package cmd

import (
	"radar/internal/scanner"

	"github.com/spf13/cobra"
)

func validateSonarQubeInputs(cmd *cobra.Command, sonarqube *scanner.Sonarqube) {
	if sonarqube.Mode == "search" {
		cmd.MarkFlagRequired("api-key")
	} else if sonarqube.Mode == "scan" {
		cmd.MarkFlagRequired("project-key")
	}
}

func init() {
	var sonarqube = &scanner.Sonarqube{}

	var sonarqubeCmd = &cobra.Command{
		Use:   "sonarqube",
		Short: "Sonarqube scanner",
		Long:  "Sonarqube scanner is a tool to scan Sonarqube projects.",
		PreRun: func(cmd *cobra.Command, args []string) {
			validateSonarQubeInputs(cmd, sonarqube)
		},
		Run: func(cmd *cobra.Command, args []string) {
			sonarqube.Init()
		},
	}

	sonarqubeCmd.PersistentFlags().StringVarP(&sonarqube.Mode, "mode", "m", "search", "sonarqube mode (search|scan|scd)")
	sonarqubeCmd.PersistentFlags().StringVarP(&sonarqube.SearchEngine, "search-engine", "", "shodan", "search engine (shodan|fofa|shodan-enterprise)")
	sonarqubeCmd.PersistentFlags().StringVarP(&sonarqube.SearchEngineApiKey, "api-key", "", "", "search engine api key")
	RootCmd.AddCommand(sonarqubeCmd)
}
