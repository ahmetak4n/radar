package sonarqube

type SonarSearchProjects struct {
	Paging SonarSearchPaging `json:"paging"`
}

type SonarSearchPaging struct {
	Total int `json:"total"`
}

type SonarSearchIssues struct {
	Facets []SonarSearchFacetsArray `json:"facets"`
}

type SonarSearchFacetsArray struct {
	Values []SonarSearchFacetsValue `json:"values"`
}

type SonarSearchFacetsValue struct {
	Val   string `json:"val"`
	Count int    `json:"count"`
}

type SonarProjectComponentTree struct {
	Paging     SonarSearchPaging          `json:"paging"`
	Components []SonarProjectSubComponent `json:"components"`
}

type SonarProjectSubComponent struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	Language  string `json:"language"`
	Qualifier string `json:"qualifier"`
}

type SonarProjectCodes struct {
	Sources []SonarProjectSource `json:"sources"`
}

type SonarProjectSource struct {
	Line int    `json:"line"`
	Code string `json:"code"`
}
