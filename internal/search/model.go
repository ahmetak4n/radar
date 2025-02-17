package search

import "radar/internal/log"

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

func (shodanSearchResult ShodanSearchResult) ToSearchResult() SearchResult {
	var searchResult SearchResult

	if shodanSearchResult.Total == 0 {
		log.Warning("The search result is empty on shodan")
		return searchResult
	}

	for _, match := range shodanSearchResult.Matches {
		searchResult.Matches = append(searchResult.Matches, Match(match))
	}

	searchResult.Total = shodanSearchResult.Total

	return searchResult
}
