package elasticsearch

// PaginatedResponse holds the paginated results and metadata
type PaginatedResponse[T any] struct {
	Items      []T   `json:"items"`       // The actual data items
	Total      int64 `json:"total"`       // Total number of items available
	Page       int   `json:"page"`        // Current page number
	PageSize   int   `json:"page_size"`   // Number of items per page
	TotalPages int   `json:"total_pages"` // Total number of pages
}

type ShodanSonarQubeSearch struct {
	Ip   string
	Port int
}
