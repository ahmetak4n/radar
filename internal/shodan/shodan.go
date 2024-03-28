package shodan

import (
	"encoding/json"

	"radar/internal/log"
	"radar/internal/model"
	"radar/internal/network"
)

func ShodanSearch(keyword string, apiKey string) *model.ResultArray {
	result := model.ResultArray{}
	url := SHODAN_API_URL + SHODAN_SEARCH_PATH + "?key=" + apiKey + "&query=" + keyword

	req, err := network.PrepareRequest(network.GetRequest, url, "")
	if err != nil {
		return nil
	}

	body, _, _, err := network.SendRequest(req)
	if err != nil {
		return nil
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		log.Stdout(log.Error, "An error occured when deserialize object", err.Error())
		return nil
	}

	return &result
}
