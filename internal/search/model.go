package search

/************************
***** Shodan Models *****
************************/
type Shodan struct {
	ApiKey  string
	License string
	Keyword string
}

type ShodanSearchResult struct {
	Matches []ShodanMatch `json:"matches"`
	Total   int           `json:"total"`
}

type ShodanMatch struct {
	Ip   string `json:"ip_str"`
	Port int    `json:"port"`
}

/************************
***** Fofa Models *****
************************/
type Fofa struct {
	ApiKey  string
	License string
	Keyword string
}
