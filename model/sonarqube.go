package model

type SonarSearchProjects struct {
	Paging	SonarSearchPaging	`json:"paging"`
}

type SonarSearchPaging struct {
	Total	int	`json:"total"`
}

type SonarSearchIssues struct {
	Facets	[]SonarSearchFacetsArray	`json:"facets"`
}

type SonarSearchFacetsArray struct {
	Values 	[]SonarSearchFacetsValue	`json:"values"`
}

type SonarSearchFacetsValue struct {
	Val		string	`json:"val"`
	Count	int		`json:"count"`
}