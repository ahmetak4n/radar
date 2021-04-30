package model

type SonarSearchProjects struct {
	Paging	SonarSearchPaging	`json:"paging"`
}

type SonarSearchPaging struct {
	Total int `json:"total"`
}