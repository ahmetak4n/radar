package search

type Searcher interface {
	Search(keyword string) ([]string, error)
	SearchWithPagination(keyword string) ([]string, error)
}
