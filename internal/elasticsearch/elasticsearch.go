package elasticsearch

import (
  "fmt"
  "bytes"
  "encoding/json"

  "github.com/elastic/go-elasticsearch/v8"  
)

// Create new Elasticsearch client
func NewClient() (*elasticsearch.Client, error) {

  cfg := elasticsearch.Config {
    Addresses: []string { 
      "http://localhost:9200",
    },
  }

  es, err := elasticsearch.NewClient(cfg)
  if err != nil {
    return nil, fmt.Errorf("Elasticsearch.NewClient ::: %w", err)    
  }

  return es, nil
}

// Generic method for put data to elasticsearch
func AddData(index string, object interface{}) (error) {

  es, err := NewClient()
  if err != nil {
    return fmt.Errorf("Elasticsearch.AddData ::: %w", err)
  }

  data, err := json.Marshal(object)
  if err != nil {
    return fmt.Errorf("Elasticsearch.AddData ::: %w", err)
  }

  _, err = es.Index(index,bytes.NewReader(data))
  if err != nil {
    return fmt.Errorf("Elasticsearch.AddData ::: %w", err)
  }

  return nil
}

func CreateIndex(index string) {
  es := NewClient()

  res, err := es.Indices.Create("radar-create")
}
