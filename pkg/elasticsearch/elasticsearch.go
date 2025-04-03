package elasticsearch

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/typedapi/core/search"
	"github.com/elastic/go-elasticsearch/v8/typedapi/types"
)

// Create new Elasticsearch client
func newTypedClient() (*elasticsearch.TypedClient, error) {

	cfg := elasticsearch.Config{
		Addresses: []string{
			Url,
		},
	}

	if Auth {
		cfg.Username = Username
		cfg.Password = Password
	}

	es, err := elasticsearch.NewTypedClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("Elasticsearch.NewClient ::: %w", err)
	}

	return es, nil
}

// Generic method for put data to specific index on elasticsearch
func AddData(index string, id string, object interface{}) error {

	es, err := newTypedClient()
	if err != nil {
		return fmt.Errorf("Elasticsearch.AddData ::: %w", err)
	}

	_, err = es.Index(index).
		Id(id).
		Request(object).
		Do(context.Background())

	if err != nil {
		return fmt.Errorf("Elasticsearch.AddData ::: %w", err)
	}

	return nil
}

// GetData retrieves documents from the specified index with pagination
// The generic type T determines the structure of the returned data
func GetAll[T any](index string, page int, pageSize int) (*PaginatedResponse[T], error) {
	es, err := newTypedClient()
	if err != nil {
		return nil, fmt.Errorf("Elasticsearch.GetData ::: %w", err)
	}

	// Calculate offset
	from := (page - 1) * pageSize

	response, err := es.Search().
		Index(index).
		Request(&search.Request{
			Query: &types.Query{
				MatchAll: &types.MatchAllQuery{},
			},
			From: &from,
			Size: &pageSize,
		}).
		Do(context.Background())

	if err != nil {
		return nil, fmt.Errorf("Elasticsearch.GetData ::: %w", err)
	}

	var results []T
	for _, hit := range response.Hits.Hits {
		var result T
		if err := json.Unmarshal(hit.Source_, &result); err != nil {
			return nil, fmt.Errorf("Elasticsearch.GetData ::: failed to decode response: %w", err)
		}
		results = append(results, result)
	}

	totalPages := int(response.Hits.Total.Value) / pageSize
	if int(response.Hits.Total.Value)%pageSize != 0 {
		totalPages++
	}

	return &PaginatedResponse[T]{
		Items:      results,
		Total:      response.Hits.Total.Value,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}
