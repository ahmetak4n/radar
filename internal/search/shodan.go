package search

import (
	"encoding/json"
	"fmt"
	"sync"

	"radar/internal/log"
	"radar/internal/network"
	"radar/pkg/elasticsearch"
)

// Search user supplied keyword on Shodan with free account
// Shodan return maximum 100 record per page if search result has more than 100 record
func (s *Shodan) Search() {
	err := s.search(1)
	if err != nil {
		log.Error("An error occured while searching on shodan", err)
	} else {
		log.Success("Shodan search completed successfully")
	}
}

// Search user supplied keyword on Shodan with paid account
// Shodan return maximum 100 record per page if search result has more than 100 record
// Then the function will visit every page one by one
// Error Group Wait used instead of Wait Group for handling request in goroutine
func (s *Shodan) EnterpriseSearch() {
	var err error
	var wg sync.WaitGroup

	recordCounts, err := s.getRecordCounts()
	if err != nil {
		log.Error("an error occured while getting record counts", err)
		return
	}

	totalPage := recordCounts / 100
	jobs := network.RequestPool(5, totalPage)

	for i := 0; i < totalPage; i++ {
		jobs <- network.PrepareRequest(network.GetRequest, fmt.Sprintf("%s?key=%s&query=%s&page=%d", SHODAN_HOST_SEARCH, s.ApiKey, s.Keyword, i), "")
	}

	wg.Wait()

	log.Success(fmt.Sprintf("shodan enterprise search completed successfully. Total record: %d - Total page: %d", recordCounts, totalPage))
}

// Get record counts that searched by keyword on Shodan
// If status code different from 200, print warning log to console
func (s *Shodan) getRecordCounts() (int, error) {
	result := ShodanSearchResult{}

	url := fmt.Sprintf("%s?key=%s&query=%s", SHODAN_HOST_COUNT, s.ApiKey, s.Keyword)

	req, err := network.PrepareRequest(network.GetRequest, url, "")
	if err != nil {
		return 0, err
	}

	body, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return 0, err
	}

	if statusCode != 200 {
		log.Warning(fmt.Sprintf("%s - request wasn't completed successfully - status code: %d", url, statusCode))
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		return 0, fmt.Errorf("an error occured while unmarshing response ::: %w", err)
	}

	return result.Total, nil
}

// Search keyword on Shodan with page parameter
// The function must use with goroutine and take waiting group as an input
// If status code different from 200, print warning log to console
func (s *Shodan) search(page int) error {
	result := ShodanSearchResult{}

	url := fmt.Sprintf("%s?key=%s&query=%s&page=%d", SHODAN_HOST_SEARCH, s.ApiKey, s.Keyword, page)

	req, err := network.PrepareRequest(network.GetRequest, url, "")
	if err != nil {
		return err
	}

	body, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return err
	}

	if statusCode != 200 {
		fmt.Println(string(body))
		return fmt.Errorf("%s - request wasn't completed successfully - status code %d", url, statusCode)
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		return fmt.Errorf("an error occured while unmarshing response ::: %w", err)
	}

	err = saveSearchResult(result)
	if err != nil {
		return fmt.Errorf("an error occured while adding data to elasticsearch ::: %w", err)
	}

	log.Success(fmt.Sprintf("shodan search completed successfully. Total record: %d - Page: %d", result.Total, page))

	return nil
}

// Write search result to Elasticsearch
// The function save every IP as a new record
func saveSearchResult(searchResult ShodanSearchResult) error {
	var err error

	for _, result := range searchResult.Matches {
		id := fmt.Sprintf("%s:%d", result.Ip, result.Port)
		err = elasticsearch.AddData("shodan-sonarqube-search", id, result)
	}

	return err
}
