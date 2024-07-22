package shodan

type SearchResult struct {
	Matches []Match `json:"matches"`
	Total   int     `json:"total"`
}

type Match struct {
	Ip   string `json:"ip_str"`
	Port int    `json:"port"`
}
