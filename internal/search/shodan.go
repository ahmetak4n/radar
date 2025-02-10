package search

import (
	"encoding/json"
	"fmt"

	"golang.org/x/sync/errgroup"

	"radar/internal/log"
	"radar/internal/network"
	"radar/pkg/elasticsearch"
)

// Search user supplied keyword on Shodan with paid account
// Shodan return maximum 100 record per page if search result has more than 100 record
// Then the function will visit every page one by one
// Error Group Wait used instead of Wait Group for handling request in goroutine
func (s *Shodan) Search() (ShodanSearchResult, error) {
	var errorGroup errgroup.Group

	result := ShodanSearchResult{}

	switch s.License {
	case "free":
		result, err := s.search(1)
		if err != nil {
			return result, fmt.Errorf("shodan.Search ::: %w", err)
		}

	case "enterprise":
		recordCounts, err := s.getRecordCounts()
		if err != nil {
			return result, fmt.Errorf("shodan.Search ::: %w", err)
		}
		totalPage := recordCounts / 100

		for i := 1; i <= totalPage; i++ {
			errorGroup.Go(func() error {
				tmpResult, err := s.search(i)
				result.Matches = append(result.Matches, tmpResult.Matches...)
				return err
			})
		}

		err = errorGroup.Wait()
		if err != nil {
			return result, fmt.Errorf("shondan.SearchEnterprise ::: %w", err)
		}
	}

	return result, nil
}

// Get record counts that searched by keyword on Shodan
// If status code different from 200, print warning log to console
func (s *Shodan) getRecordCounts() (int, error) {
	result := ShodanSearchResult{}

	url := fmt.Sprintf("%s?key=%s&query=%s", SHODAN_HOST_COUNT, s.ApiKey, s.Keyword)

	req, err := network.PrepareRequest(network.GetRequest, url, "")
	if err != nil {
		return 0, fmt.Errorf("shondan.getRecordCounts ::: %w", err)
	}

	body, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return 0, fmt.Errorf("shondan.getRecordCounts ::: %w", err)
	}

	if statusCode != 200 {
		log.Warning(fmt.Sprintf("%s - Request wasn't completed successfully ::: Status Code %d", url, statusCode))
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		return 0, fmt.Errorf("shondan.getRecordCounts ::: An error occured while unmarshing response ::: %w", err)
	}

	return result.Total, nil
}

// Search keyword on Shodan with page parameter
// The function must use with goroutine and take waiting group as an input
// If status code different from 200, print warning log to console
func (s *Shodan) search(page int) (ShodanSearchResult, error) {
	result := ShodanSearchResult{}

	url := fmt.Sprintf("%s?key=%s&query=%s&page=%d", SHODAN_HOST_SEARCH, s.ApiKey, s.Keyword, page)

	req, err := network.PrepareRequest(network.GetRequest, url, "")
	if err != nil {
		return result, fmt.Errorf("shondan.searchWithPagination ::: %w", err)
	}

	body, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return result, fmt.Errorf("shondan.searchWithPagination ::: %w", err)
	}

	if statusCode != 200 {
		return result, fmt.Errorf("%s - Request wasn't completed successfully ::: Status Code %d", url, statusCode)
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		return result, fmt.Errorf("shondan.searchWithPagination ::: An error occured while unmarshing response ::: %w", err)
	}

	err = saveSearchResult(result)
	if err != nil {
		return result, fmt.Errorf("shondan.searchWithPagination ::: An error occured while adding data to Elasticsearch ::: %w", err)
	}

	return result, nil
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
