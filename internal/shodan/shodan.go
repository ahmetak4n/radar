package shodan

import (
	"encoding/json"
	"fmt"
  "golang.org/x/sync/errgroup"

	"radar/internal/log"
	"radar/internal/network"
)

// Search user supplied keyword on Shodan
// Shodan return maximum 100 record per page if search result has more than 100 record
// Then the function will visit every page one by one
// Error Group Wait used instead of Wait Group for handling request in goroutine
func Search(apiKey, keyword string) (SearchResult, error) {
	var errorGroup errgroup.Group

	result := SearchResult{}

	recordCounts, err := getRecordCounts(apiKey, keyword)
	if err != nil {
		return result, fmt.Errorf("Shodan.Search ::: %w", err)
	}

	totalPage := recordCounts / 100
	// Remove ::: Will be remove after SQL integration
	totalPage = 1

	for i := 1; i <= totalPage; i++ {
		errorGroup.Go(func() (error) {
      tmpResult, err := searchWithPagination(keyword, apiKey, i)
      result.Matches = append(result.Matches, tmpResult.Matches...)

      return err
		})
	}

  err = errorGroup.Wait()
  if err != nil {
    return result, fmt.Errorf("Shondan.Search ::: %w", err)
  }

	return result, nil
}

// Get record counts that searched by keyword on Shodan
// If status code different from 200, print warning log to console
func getRecordCounts(apiKey, keyword string) (int, error) {
	result := SearchResult{}

	url := fmt.Sprintf("%s?key=%s&query=%s", SHODAN_HOST_COUNT_PATH, apiKey, keyword)

	req, err := network.PrepareRequest(network.GetRequest, url, "")
	if err != nil {
		return 0, fmt.Errorf("Shondan.getRecordCounts ::: %w", err)
	}

	body, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return 0, fmt.Errorf("Shondan.getRecordCounts ::: %w", err)
	}

	if statusCode != 200 {
		log.Stdout(log.Warning, fmt.Sprintf("%s - Request wasn't completed successfully ::: Status Code %d", url, statusCode), "")
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		return 0, fmt.Errorf("Shondan.getRecordCounts ::: An error occured while unmarshing response ::: %w", err)
	}

	return result.Total, nil
}

// Search keyword on Shodan with page parameter
// The function must use with goroutine and take waiting group as an input
// If status code different from 200, print warning log to console
func searchWithPagination(keyword string, apiKey string, page int) (SearchResult, error) {
	result := SearchResult{}

	url := fmt.Sprintf("%s?key=%s&query=%s&page=%d", SHODAN_HOST_SEARCH_PATH, apiKey, keyword, page)

	req, err := network.PrepareRequest(network.GetRequest, url, "")
	if err != nil {
		return result, fmt.Errorf("Shondan.searchWithPagination ::: %w", err)
	}

	body, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return result, fmt.Errorf("Shondan.searchWithPagination ::: %w", err)
	}

	if statusCode != 200 {
		log.Stdout(log.Error, fmt.Sprintf("%s - Request wasn't completed successfully ::: Status Code %d", url, statusCode), "")
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		return result, fmt.Errorf("Shondan.searchWithPagination ::: An error occured while unmarshing response ::: %w", err)
	}

	return result, nil
}
