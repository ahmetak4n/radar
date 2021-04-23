package model

type ResultArray struct {
	Matches []SearchResult	`json:"matches"`
}

type SearchResult struct {
	Ip_str 		string 		`json:"ip_str"`
	Port 		int			`json:"port"`
	Isp			string		`json:"isp"`
	Hostnames	[]string 	`json:"hostnames"`
	Domains		[]string 	`json:"domains"`
	Location 	location	`json:"location"`
}

type location struct {
	City			string 	`json:"city"`
	Region_code		string	`json:"region_code"`
	Country_code	string	`json:"country_code"`
	Country_name	string	`json:"country_name"`
	Longitude		float64	`json:"longitude"`
	Latitude		float64	`json:"latitude"`
}