package scan

const (
	//TODO - SSL NOT SUPPORTED YET
	SONARQUBE_BASE_URL = "http://%s:%d%s"

	SONARQUBE_API_AUTHENTICATION_LOGIN       = "/api/authentication/login"
	SONARQUBE_API_USER_CURRENT               = "/api/users/current"
	SONARQUBE_API_COMPONENTS_SEARCH_PROJECTS = "/api/components/search_projects"
	SONARQUBE_API_ISSUE_SEARCH               = "/api/issues/search?resolved=false&facets=types&ps=1&additionalFields=_all"

	SONARQUBE_PROJECT_COMPONENT_PATH  = "/api/measures/component_tree?"
	SONARQUBE_PROJECT_COMPONENT_PARAM = "metricKeys=ncloc&component=%s&p=%d&ps=%d"

	//TODO - It will change with /api/sources/raw?
	SONARQUBE_PROJECT_SOURCE_CODE_PATH = "/api/sources/lines?key=%s"

	SONARQUBE_DEFAULT_USER     = "admin"
	SONARQUBE_DEFAULT_PASSWORD = "admin"
)
