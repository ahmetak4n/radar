package search

type SearchResult struct {
	Matches []Match
	Total   int
}

type Match struct {
	Ip   string
	Port int
}

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

type Fofa struct {
	ApiKey  string
	License string
	Keyword string
}
