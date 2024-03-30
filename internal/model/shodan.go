package model

type ResultArray struct {
	Matches []SearchResult `json:"matches"`
}

type SearchResult struct {
	Ip_str    string         `json:"ip_str"`
	Port      int            `json:"port"`
	Isp       string         `json:"isp"`
	Hostnames []string       `json:"hostnames"`
	Domains   []string       `json:"domains"`
	Location  ShodanLocation `json:"location"`
	Http      ShodanHttp     `json:"http"`
	Ssl       ShodanSsl      `json:"ssl"`
}

type ShodanHttp struct {
	Host string `json:"host"`
}

type ShodanSsl struct {
	Jarm string `json:"jarm"`
}

type ShodanLocation struct {
	City         string  `json:"city"`
	Region_code  string  `json:"region_code"`
	Country_code string  `json:"country_code"`
	Country_name string  `json:"country_name"`
	Longitude    float64 `json:"longitude"`
	Latitude     float64 `json:"latitude"`
}

