package core

import (
	"encoding/json"

	"radar/model"
)

var (
	SHODAN_API_URL = "https://api.shodan.io"
	SHODAN_SEARCH_PATH = "/shodan/host/search"
)

func ShodanSearch(keyword string, apiKey string) (*model.ResultArray) {
	result := model.ResultArray{}
	url := SHODAN_API_URL + SHODAN_SEARCH_PATH + "?key=" + apiKey + "&query=" + keyword
	
	req, err := PrepareRequest("GET", url, "")
	if (err != nil) {
		return nil
	}

	body, _, _, err := SendRequest(req)
	if (err != nil) {
		return nil
	}

	err = json.Unmarshal([]byte(body), &result)
	if (err != nil) {
		CustomLogger("error", "An error occured when deserialize object", err.Error())
		return nil
	}

	return &result
}