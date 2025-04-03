package scanner

import (
	"flag"
)

type Sonarqube struct {
	Menu           *flag.FlagSet
	ModeSearchMenu *flag.FlagSet

	Mode string

	SearchEngine       string
	SearchEngineApiKey string

	ElasticUrl string

	Port       int
	Hostname   string
	ProjectKey string
}

type SonarqubeSearchProject struct {
	Paging SonarQubePaging `json:"paging"`
}

type SonarQubePaging struct {
	Total int `json:"total"`
}

type SonarQubeIssues struct {
	Facets []SonarQubeFacet `json:"facets"`
}

type SonarQubeFacet struct {
	Values []SonarQubeValue `json:"values"`
}

type SonarQubeValue struct {
	Val   string `json:"val"`
	Count int    `json:"count"`
}

type SonarQubeComponentTree struct {
	Paging     SonarQubePaging      `json:"paging"`
	Components []SonarQubeComponent `json:"components"`
}

type SonarQubeComponent struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	Language  string `json:"language"`
	Qualifier string `json:"qualifier"`
}

type SonarQubeLine struct {
	Sources []SonarQubeSource `json:"sources"`
}

type SonarQubeSource struct {
	Line int    `json:"line"`
	Code string `json:"code"`
}

type SonarQubeDetail struct {
	Ip                   string
	Port                 int
	Version              string
	IsAccessible         bool
	IsPublic             bool
	IsDefaultCredential  bool
	ProjectCount         int
	CodeSmellCount       int
	VulnerabilityCount   int
	BugCount             int
	SecurityHotspotCount int
}
