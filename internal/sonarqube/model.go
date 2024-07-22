package sonarqube

import (
	"flag"
)

type Scanner struct {
	Menu *flag.FlagSet

	AttackType string

	ShodanApiKey string

	Port       int
	Hostname   string
	ProjectKey string
}

type SearchProject struct {
	Paging Paging `json:"paging"`
}

type Paging struct {
	Total int `json:"total"`
}

type Issues struct {
	Facets []Facet `json:"facets"`
}

type Facet struct {
	Values []Value `json:"values"`
}

type Value struct {
	Val   string `json:"val"`
	Count int    `json:"count"`
}

type ComponentTree struct {
	Paging     Paging      `json:"paging"`
	Components []Component `json:"components"`
}

type Component struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	Language  string `json:"language"`
	Qualifier string `json:"qualifier"`
}

type Line struct {
	Sources []Source `json:"sources"`
}

type Source struct {
	Line int    `json:"line"`
	Code string `json:"code"`
}
