package core

import (
	"io/ioutil"
	"encoding/json"

	"radar/model"
)

var (
	SHODAN_API_URL = "https://api.shodan.io"
	SHODAN_API_KEY = ""
	SHODAN_SEARCH_PATH = "/shodan/host/search"
)

func ShodanSearch(keyword string) (*model.ResultArray) {
	url := SHODAN_API_URL + SHODAN_SEARCH_PATH + "?key=" + SHODAN_API_KEY + "&query=" + keyword
	req := PrepareRequest("GET", url, "")

	res, _ := SendRequest(req)

	body, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()

	ErrorLog(err, "An error occured when reading response body in ShodanSearch")

	result := model.ResultArray{}
	err = json.Unmarshal([]byte(body), &result)

	ErrorLog(err, "An error occured when deserialize object")

	return &result
}