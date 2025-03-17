package elasticsearch

import (
	"context"
	"fmt"

	"github.com/elastic/go-elasticsearch/v8"
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
