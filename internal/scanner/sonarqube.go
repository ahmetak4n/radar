package scanner

import (
	"encoding/json"
	"fmt"
	"time"

	"sync"

	"radar/internal/log"
	"radar/internal/network"
	"radar/internal/search"

	"radar/pkg/elasticsearch"
)

// Initialize sonarqube scanner
func (sonarqube Sonarqube) Init() {
	switch sonarqube.Mode {
	case "search":
		sonarqube.Search()
	case "scan":
		sonarqube.Scan()
	case "scd":
		//sonarqube.Scd()
	}
}

// Search sonarqube instance on search engines
func (sonarqube Sonarqube) Search() {
	switch sonarqube.SearchEngine {
	case "shodan":
		shodan := search.Shodan{
			ApiKey:  sonarqube.SearchEngineApiKey,
			Keyword: "sonarqube",
			License: "free",
		}
		shodan.Search()
	case "shodan-enterprise":
		shodan := search.Shodan{
			ApiKey:  sonarqube.SearchEngineApiKey,
			Keyword: "sonarqube",
			License: "enterprise",
		}
		shodan.EnterpriseSearch()
	}
}

// Detect misconfigured sonarqubes and show details
func (sonarqube Sonarqube) Scan() {
	var wg sync.WaitGroup

	results, err := GetAllSonarQubeProjects()
	if err != nil {
		log.Error("Error getting data from elasticsearch", err)
		return
	}

	wg.Add(len(results))

	for i, result := range results {
		go func(ip string, port int, subwg *sync.WaitGroup) {
			sd := SonarQubeDetail{
				Ip:           ip,
				Port:         port,
				IsAccessible: false,
				IsPublic:     false,
			}

			sd.getSonarQubeDetail(subwg)
		}(result.Ip, result.Port, &wg)

		// Sleep for 5 seconds after every 500 requests
		// Otherwise, elasticsearch drops the connections
		if i%500 == 0 {
			time.Sleep(time.Second * 5)
		}
	}

	wg.Wait()
}

// Get details on detected SonarQube
// Like issue, vulnerability, code smell counts, etc.
func (sonarQubeDetail *SonarQubeDetail) getSonarQubeDetail(wg *sync.WaitGroup) {
	defer func() {
		sonarQubeDetail.saveToElasticsearch()
		wg.Done()
	}()

	statusCode, err := sonarQubeDetail.isAccessible()
	if err != nil {
		log.Error(fmt.Sprintf("An error occured when checking SonarQube accessibility - %s:%d", sonarQubeDetail.Ip, sonarQubeDetail.Port), err)
		return
	} else if statusCode != 200 {
		log.Fail(fmt.Sprintf("SonarQube Instance Not Accessible - Status Code: %d - %s:%d", statusCode, sonarQubeDetail.Ip, sonarQubeDetail.Port))
		return
	} else {
		log.Success(fmt.Sprintf("SonarQube Instance Accessible - %s:%d", sonarQubeDetail.Ip, sonarQubeDetail.Port))
	}

	statusCode, err = sonarQubeDetail.getVersion()
	if err != nil {
		log.Error(fmt.Sprintf("An error occured when getting sonarQube version - %s:%d", sonarQubeDetail.Ip, sonarQubeDetail.Port), err)
	} else if statusCode != 200 {
		log.Fail(fmt.Sprintf("SonarQube Version Not Found - Status Code: %d - %s:%d", statusCode, sonarQubeDetail.Ip, sonarQubeDetail.Port))
	} else {
		log.Success(fmt.Sprintf("SonarQube Version Found - %s", sonarQubeDetail.Version))
	}

	statusCode, err = sonarQubeDetail.isPublic()
	if err != nil {
		log.Error(fmt.Sprintf("An error occured when checking SonarQube projects accessibility - %s:%d", sonarQubeDetail.Ip, sonarQubeDetail.Port), err)
	} else if statusCode != 200 {
		log.Fail(fmt.Sprintf("SonarQube Has No Public Projects - Status Code: %d - %s:%d", statusCode, sonarQubeDetail.Ip, sonarQubeDetail.Port))
	} else {
		log.Success(fmt.Sprintf("SonarQube Has Public Projects - %s:%d", sonarQubeDetail.Ip, sonarQubeDetail.Port))
	}

	statusCode, err = sonarQubeDetail.isDefaultCredential()
	if err != nil {
		log.Error(fmt.Sprintf("An error occured when checking SonarQube default credentials - %s:%d", sonarQubeDetail.Ip, sonarQubeDetail.Port), err)
	} else if statusCode != 200 {
		log.Fail(fmt.Sprintf("Default Credentials Not Work on SonarQube - Status Code: %d - %s:%d", statusCode, sonarQubeDetail.Ip, sonarQubeDetail.Port))
	} else {
		log.Success(fmt.Sprintf("Default Credentials Work on SonarQube - %s:%d", sonarQubeDetail.Ip, sonarQubeDetail.Port))
	}

	if sonarQubeDetail.IsPublic {
		statusCode, err = sonarQubeDetail.getProjectCount()
		if err != nil {
			log.Error(fmt.Sprintf("An error occured when getting SonarQube project count - %s:%d", sonarQubeDetail.Ip, sonarQubeDetail.Port), err)
			return
		} else if statusCode != 200 {
			log.Fail(fmt.Sprintf("SonarQube Has No Projects - Status Code: %d - %s:%d", statusCode, sonarQubeDetail.Ip, sonarQubeDetail.Port))
		} else {
			log.Success(fmt.Sprintf("SonarQube Has Projects - %d", sonarQubeDetail.ProjectCount))
		}

		if sonarQubeDetail.ProjectCount > 0 {
			err = sonarQubeDetail.getIssuesCount()
			if err != nil {
				log.Error(fmt.Sprintf("An error occured when getting SonarQube issues details - %s:%d", sonarQubeDetail.Ip, sonarQubeDetail.Port), err)
			}

			log.Success(fmt.Sprintf(
				"Public Project Accessible! - %s:%d\n[*******] Project Count: %d, Code Smell: %d, Vulnerability: %d, Bug: %d, Security Hotspot: %d",
				sonarQubeDetail.Ip, sonarQubeDetail.Port, sonarQubeDetail.ProjectCount, sonarQubeDetail.CodeSmellCount, sonarQubeDetail.VulnerabilityCount,
				sonarQubeDetail.BugCount, sonarQubeDetail.SecurityHotspotCount))
		}
	}
}

// Check the SonarQube instance projects are accessible
func (sonarQubeDetail *SonarQubeDetail) isAccessible() (int, error) {
	var err error

	req, err := network.PrepareRequest(network.GetRequest, fmt.Sprintf(SONARQUBE_BASE_URL, sonarQubeDetail.Ip, sonarQubeDetail.Port, "/"), "")
	if err != nil {
		return 0, fmt.Errorf("sonarqube.isAccessible ::: %w ", err)
	}

	_, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return 0, fmt.Errorf("sonarqube.isAccessible ::: %w ", err)
	}

	if statusCode == 200 {
		sonarQubeDetail.IsAccessible = true
	}

	return statusCode, err
}

// Get the version of the SonarQube instance
func (sonarQubeDetail *SonarQubeDetail) getVersion() (int, error) {
	var err error

	req, err := network.PrepareRequest(network.GetRequest, fmt.Sprintf(SONARQUBE_BASE_URL, sonarQubeDetail.Ip, sonarQubeDetail.Port, SONARQUBE_API_SERVER_VERSION), "")
	if err != nil {
		return 0, fmt.Errorf("sonarqube.checkVersion ::: %w ", err)
	}

	response, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return 0, fmt.Errorf("sonarqube.checkVersion ::: %w ", err)
	}

	if statusCode == 200 {
		sonarQubeDetail.Version = string(response)
	}

	return statusCode, err
}

// Check the SonarQube instance projects are accessible
func (sonarQubeDetail *SonarQubeDetail) isPublic() (int, error) {
	var err error

	req, err := network.PrepareRequest(network.GetRequest, fmt.Sprintf(SONARQUBE_BASE_URL, sonarQubeDetail.Ip, sonarQubeDetail.Port, SONARQUBE_API_USER_CURRENT), "")
	if err != nil {
		return 0, fmt.Errorf("sonarqube.isPublic ::: %w ", err)
	}

	_, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return 0, fmt.Errorf("sonarqube.isPublic ::: %w ", err)
	}

	if statusCode == 200 {
		sonarQubeDetail.IsPublic = true
	}

	return statusCode, err
}

// Get the count of projects on the SonarQube instance
func (sonarQubeDetail *SonarQubeDetail) getProjectCount() (int, error) {
	var err error
	var result SonarqubeSearchProject

	req, err := network.PrepareRequest(network.GetRequest, fmt.Sprintf(SONARQUBE_BASE_URL, sonarQubeDetail.Ip, sonarQubeDetail.Port, SONARQUBE_API_COMPONENTS_SEARCH_PROJECTS), "")
	if err != nil {
		return 0, fmt.Errorf("sonarqube.getProjectCount ::: %w ", err)
	}

	body, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return 0, fmt.Errorf("sonarqube.getProjectCount ::: %w ", err)
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		return 0, fmt.Errorf("sonarqube.getProjectCount ::: %w", err)
	}

	if statusCode == 200 {
		sonarQubeDetail.ProjectCount = result.Paging.Total
	}

	return statusCode, err
}

// Get the count of issues on the SonarQube instance
func (sonarQubeDetail *SonarQubeDetail) getIssuesCount() error {
	var err error
	var result SonarQubeIssues

	req, err := network.PrepareRequest(network.GetRequest, fmt.Sprintf(SONARQUBE_BASE_URL, sonarQubeDetail.Ip, sonarQubeDetail.Port, SONARQUBE_API_ISSUE_SEARCH), "")
	if err != nil {
		return fmt.Errorf("sonarqube.getIssuesCount ::: %w", err)
	}

	body, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return fmt.Errorf("sonarqube.getIssuesCount ::: %w", err)
	} else if statusCode != 200 {
		return fmt.Errorf("status code %d ::: sonarqube.getIssuesCount ::: %w ", statusCode, err)
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		return fmt.Errorf("sonarqube.getIssuesCount ::: %w", err)
	}

	if result.Facets != nil {
		for _, data := range result.Facets[0].Values {
			switch data.Val {
			case "CODE_SMELL":
				sonarQubeDetail.CodeSmellCount = data.Count
			case "VULNERABILITY":
				sonarQubeDetail.VulnerabilityCount = data.Count
			case "BUG":
				sonarQubeDetail.BugCount = data.Count
			case "SECURITY_HOTSPOT":
				sonarQubeDetail.SecurityHotspotCount = data.Count
			}
		}
	}

	return err
}

func (sonarQubeDetail *SonarQubeDetail) isDefaultCredential() (int, error) {
	var err error

	req, err := network.PrepareRequest(network.PostRequest, fmt.Sprintf(SONARQUBE_BASE_URL, sonarQubeDetail.Ip, sonarQubeDetail.Port, SONARQUBE_API_AUTHENTICATION_LOGIN),
		fmt.Sprintf("login=%s&password=%s", SONARQUBE_DEFAULT_USER, SONARQUBE_DEFAULT_PASSWORD))
	if err != nil {
		return 0, fmt.Errorf("sonarqube.isDefaultCredential ::: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return 0, fmt.Errorf("sonarqube.isDefaultCredential ::: %w", err)
	}

	if statusCode == 200 {
		sonarQubeDetail.IsDefaultCredential = true
	}

	return statusCode, err
}

func (sonarQubeDetail *SonarQubeDetail) saveToElasticsearch() {
	id := fmt.Sprintf("%s:%d", sonarQubeDetail.Ip, sonarQubeDetail.Port)
	err := elasticsearch.AddData("sonarqube-db", id, sonarQubeDetail)
	if err != nil {
		log.Error(fmt.Sprintf("An error occured when adding data to elasticsearch - %s:%d - %s", sonarQubeDetail.Ip, sonarQubeDetail.Port, err.Error()), err)
	}
}

func GetAllSonarQubeProjects() ([]elasticsearch.ShodanSonarQubeSearch, error) {
	var err error
	var results []elasticsearch.ShodanSonarQubeSearch

	totalPages := 1

	for i := 1; i <= totalPages; i++ {
		paginationResponse, err := elasticsearch.GetAll[elasticsearch.ShodanSonarQubeSearch]("shodan-sonarqube-search", i, 100)
		if err != nil {
			return nil, fmt.Errorf("Elasticsearch.GetData ::: %w", err)
		}

		results = append(results, paginationResponse.Items...)
		totalPages = paginationResponse.TotalPages
	}

	return results, err
}

/*func (sonarqube Sonarqube) Scd() {
	var wg sync.WaitGroup
	components := getSonarQubeProjectFiles(sonarqube.Hostname, sonarqube.Port, sonarqube.ProjectKey, 1, 500)

	if components == nil {
		log.Warning("Could not found any code folder!")
		return
	}

	for i, fileComponent := range components {
		if utils.Contains(fileComponent.Name, utils.CommonFileExtensions()) {
			go func(file Component) {
				wg.Add(1)
				createSourceCodeFileViaSonarQube(sonarqube.Hostname, sonarqube.Port, sonarqube.ProjectKey, file, &wg)
			}(fileComponent)
		}

		if i%5 == 0 {
			wg.Wait()
		}
	}

	wg.Wait()
}

func createSourceCodeFileViaSonarQube(hostname string, port int, projectKey string, file Component, wg *sync.WaitGroup) {
	defer wg.Done()

	path := strings.Split(file.Path, file.Name)[0]

	err := utils.CreateFolder("scd/" + projectKey + "/" + path)
	if err != nil {
		return
	}

	f, err := utils.CreateFile("scd/" + projectKey + "/" + file.Path)
	if err != nil {
		return
	}

	log.Warning(file.Key + " downloading")
	codeArray := getSonarQubeProjectCodes(hostname, port, file.Key)

	if codeArray == nil {
		log.Error(file.Key+" was not downloaded", err)
		return
	}

	_, err = f.WriteString("//This code fetched by Radar")
	if err != nil {
		log.Error("An error occured when writing file"+file.Key, err)
	}

	for _, line := range codeArray.Sources {
		c := clearHtmlTagFromSonarQubeCodeFile(line.Code)

		_, err = f.WriteString("\n" + c)
		if err != nil {
			log.Error("An error occured when writing file"+file.Key, err)
		}
	}

	err = f.Close()
	if err != nil {
		log.Error("An error occured when closed"+file.Key, err)
	}
}

func getSonarQubeProjectFiles(hostname string, port int, projectKey string, page int, count int) []Component {
	result := &ComponentTree{}

	req, err := network.PrepareRequest(network.GetRequest, fmt.Sprintf(BASE_URL, hostname, port, PROJECT_COMPONENT_PATH+fmt.Sprintf(PROJECT_COMPONENT_PARAM, projectKey, page, count)), "")
	if err != nil {
		return nil
	}

	body, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return nil
	}

	if statusCode != 200 {
		log.Error("Server return error code "+strconv.Itoa(statusCode)+" when fetching code folder", err)
		return nil
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		log.Error("An error occured when deserialize object", err)
		return nil
	}

	if float64(result.Paging.Total)/float64(count) > float64(page) {
		result.Components = append(result.Components, getSonarQubeProjectFiles(hostname, port, projectKey, page+1, count)...)
	}

	return result.Components
}

func getSonarQubeProjectCodes(hostname string, port int, projectKey string) *Line {
	result := &Line{}

	req, err := network.PrepareRequest(network.GetRequest, fmt.Sprintf(BASE_URL, hostname, port, fmt.Sprintf(PROJECT_SOURCE_CODE_PATH, projectKey)), "")
	if err != nil {
		return nil
	}

	body, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return nil
	}

	if statusCode != 200 {
		log.Error("Server return error code "+strconv.Itoa(statusCode), err)
		return nil
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		log.Error("An error occured when deserialize object", err)
		return nil
	}

	return result
}

func clearHtmlTagFromSonarQubeCodeFile(code string) string {
	regex := regexp.MustCompile(`<.*?>`)
	c := regex.ReplaceAllString(code, "")
	c = html.UnescapeString(c)

	return c
}
*/
