package sonarqube

const (
	//TODO - SSL NOT SUPPORTED YET
	BASE_URL = "http://%s:%d%s"

	API_AUTHENTICATION_LOGIN       = "/api/authentication/login"
	API_USER_CURRENT               = "/api/users/current"
	API_COMPONENTS_SEARCH_PROJECTS = "/api/components/search_projects"
	API_ISSUE_SEARCH               = "/api/issues/search?resolved=false&facets=types&ps=1&additionalFields=_all"

	PROJECT_COMPONENT_PATH  = "/api/measures/component_tree?"
	PROJECT_COMPONENT_PARAM = "metricKeys=ncloc&component=%s&p=%d&ps=%d"

	//TODO - It will change with /api/sources/raw?
	PROJECT_SOURCE_CODE_PATH = "/api/sources/lines?key=%s"

	DEFAULT_USER     = "admin"
	DEFAULT_PASSWORD = "admin"
)
