package scanner

import (
	"encoding/json"
	"flag"
	"fmt"

	"net"
	"sync"

	"radar/internal/log"
	"radar/internal/network"
	"radar/internal/search"

	"radar/pkg/elasticsearch"
)

// Parse user supplied parameter and create a sonarqube scanner
func NewSonarqube() *Sonarqube {
	sonarqube := &Sonarqube{}

	menu := flag.NewFlagSet("sonarqube", flag.ExitOnError)

	menu.StringVar(&sonarqube.AttackType, "aT", "scan", "attack type: scan | scd (source code download)")
	menu.StringVar(&sonarqube.SearchEngine, "sE", "shodan", "search engine: shodan | fofa | shodan-enterprise")
	menu.StringVar(&sonarqube.SearchEngineApiKey, "aK", "", "search engine api key (Required when attacktype scan)")
	menu.IntVar(&sonarqube.Port, "p", 9000, "sonarqube port (Required when attacktype scd)")
	menu.StringVar(&sonarqube.Hostname, "host", "", "sonarqube hostname or Ip (Required when attacktype scd)")
	menu.StringVar(&sonarqube.ProjectKey, "pK", "", "project key that want to download source code (Required when attacktype scd)")
	menu.BoolVar(&log.VERBOSE, "v", false, "verbose mode")

	sonarqube.Menu = menu

	return sonarqube
}

// Detect misconfigured sonarqubes and show details
func (sonarqube Sonarqube) Scan() {
	var wg sync.WaitGroup
	var searchResult search.SearchResult

	searchResult, err := sonarqube.search()
	if err != nil {
		log.Error(fmt.Sprintf("an error occured while during search on %s", sonarqube.SearchEngine), err)
		return
	}

	for _, result := range searchResult.Matches {
		connection, err := network.HostConnection(result.Ip, result.Port)

		if err != nil {
			log.Error("", err)
			break
		}

		go func(r search.Match, c net.Conn) {
			defer c.Close()
			wg.Add(2)
			checkSonarQubeDetail(r, &wg)
			//checkDefaultCredential(r, &wg)
		}(result, connection)
	}

	wg.Wait()
}

// Search sonarqube instance on search engines
func (sonarqube Sonarqube) search() (search.SearchResult, error) {
	var err error
	var searchResult search.SearchResult

	switch sonarqube.SearchEngine {
	case "shodan":
		shodan := search.Shodan{
			ApiKey:  sonarqube.SearchEngineApiKey,
			Keyword: "sonarqube",
			License: "free",
		}
		searchResult, err = shodan.Search()
	case "shodan-enterprise":
		shodan := search.Shodan{
			ApiKey:  sonarqube.SearchEngineApiKey,
			Keyword: "sonarqube",
			License: "enterprise",
		}
		searchResult, err = shodan.EnterpriseSearch()
	}

	return searchResult, err
}

// Get details on detected SonarQube
// Like issue, vulnerability, code smell counts, etc.
func checkSonarQubeDetail(searchResult search.Match, wg *sync.WaitGroup) {
	defer wg.Done()

	var err error
	sonarQubeDetail := SonarQubeDetail{
		Ip:   searchResult.Ip,
		Port: searchResult.Port,
	}

	sonarQubeDetail.Version, err = getSonarQubeVersion(sonarQubeDetail.Ip, sonarQubeDetail.Port)
	if err != nil {
		return
	}

	sonarQubeDetail.Accessible, sonarQubeDetail.StatusCode, err = isSonarQubeAccessible(sonarQubeDetail.Ip, sonarQubeDetail.Port)
	if err != nil && sonarQubeDetail.StatusCode != 200 {
		return
	}

	sonarQubeDetail.ProjectCount, err = getSonarQubeProjectCount(sonarQubeDetail.Ip, sonarQubeDetail.Port)
	if err != nil {
		return
	}

	if sonarQubeDetail.ProjectCount > 0 {
		sonarQubeDetail.CodeSmellCount, sonarQubeDetail.VulnerabilityCount, sonarQubeDetail.BugCount, sonarQubeDetail.SecurityHotspotCount = getSonarQubeIssuesCount(sonarQubeDetail.Ip, sonarQubeDetail.Port)
		log.Success(fmt.Sprintf(
			"SonarQube Projects Accessible! - %s:%d\n[*******] Project Counts: %d, Code Smell: %d, Vulnerability: %d, Bug: %d, Security Hotspot: %d",
			sonarQubeDetail.Ip, sonarQubeDetail.Port, sonarQubeDetail.ProjectCount, sonarQubeDetail.CodeSmellCount, sonarQubeDetail.VulnerabilityCount, sonarQubeDetail.BugCount, sonarQubeDetail.SecurityHotspotCount))
	} else {
		log.Success(fmt.Sprintf("SonarQube Projects Accessible But Empty - %s:%d", sonarQubeDetail.Ip, sonarQubeDetail.Port))
	}

	fmt.Println(sonarQubeDetail)

	saveToElasticsearch(sonarQubeDetail)
}

// Check the SonarQube instance projects are accessible
func isSonarQubeAccessible(ip string, port int) (bool, int, error) {
	var err error

	req, err := network.PrepareRequest(network.GetRequest, fmt.Sprintf(SONARQUBE_BASE_URL, ip, port, SONARQUBE_API_USER_CURRENT), "")
	if err != nil {
		log.Error("sonarqube.checkSonarQubeDetail ::: ", err)
		return false, 0, err
	}

	_, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		log.Error("sonarqube.checkSonarQubeDetail ::: ", err)
		return false, 0, err
	}

	if statusCode == 401 || statusCode == 403 {
		log.Fail(fmt.Sprintf("SonarQube Projects Not Accessible - %s:%d", ip, port))
		return false, statusCode, err
	} else if statusCode != 200 {
		log.Fail(fmt.Sprintf("SonarQube Return %d Status Code - %s:%d", statusCode, ip, port))
		return false, statusCode, err
	}

	return true, statusCode, err
}

// Get the version of the SonarQube instance
func getSonarQubeVersion(ip string, port int) (string, error) {
	var err error

	req, err := network.PrepareRequest(network.GetRequest, fmt.Sprintf(SONARQUBE_BASE_URL, ip, port, SONARQUBE_API_SERVER_VERSION), "")
	if err != nil {
		log.Error("sonarqube.checkSonarQubeDetail ::: ", err)
		return "", err
	}

	response, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		log.Error("sonarqube.checkSonarQubeDetail ::: ", err)
		return "", err
	} else if statusCode != 200 {
		log.Error(fmt.Sprintf("sonarqube.getSonarQubeVersion ::: SonarQube Return %d Status Code - %s:%d", statusCode, ip, port), nil)
		return "", err
	}

	return string(response), err
}

// Get the count of projects on the SonarQube instance
func getSonarQubeProjectCount(ip string, port int) (int, error) {
	var result SonarqubeSearchProject

	req, err := network.PrepareRequest(network.GetRequest, fmt.Sprintf(SONARQUBE_BASE_URL, ip, port, SONARQUBE_API_COMPONENTS_SEARCH_PROJECTS), "")
	if err != nil {
		return 0, err
	}

	body, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		return 0, err
	}

	if statusCode != 200 {
		log.Error(fmt.Sprintf("sonarqube.getSonarQubeProjectCount ::: SonarQube Return %d Status Code - %s:%d", statusCode, ip, port), nil)
		return 0, err
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		return 0, err
	}

	return result.Paging.Total, err
}

// Get the count of issues on the SonarQube instance
func getSonarQubeIssuesCount(ip string, port int) (int, int, int, int) {
	result := SonarQubeIssues{}
	codeSmell, vulnerability, bug, securityHotspot := 0, 0, 0, 0

	req, err := network.PrepareRequest(network.GetRequest, fmt.Sprintf(SONARQUBE_BASE_URL, ip, port, SONARQUBE_API_ISSUE_SEARCH), "")
	if err != nil {
		log.Error("sonarqube.getSonarQubeIssuesCount ::: ", err)
		return 0, 0, 0, 0
	}

	body, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		log.Error("sonarqube.getSonarQubeIssuesCount ::: ", err)
		return 0, 0, 0, 0
	}

	if statusCode != 200 {
		log.Error(fmt.Sprintf("sonarqube.getSonarQubeIssuesCount ::: SonarQube Return %d Status Code - %s:%d", statusCode, ip, port), nil)
		return 0, 0, 0, 0
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		log.Error("sonarqube.getSonarQubeIssuesCount ::: An error occured when deserialize object", err)
		return 0, 0, 0, 0
	}

	if result.Facets != nil {
		for _, data := range result.Facets[0].Values {
			switch data.Val {
			case "CODE_SMELL":
				codeSmell = data.Count
			case "VULNERABILITY":
				vulnerability = data.Count
			case "BUG":
				bug = data.Count
			case "SECURITY_HOTSPOT":
				securityHotspot = data.Count
			}
		}
	}

	return codeSmell, vulnerability, bug, securityHotspot
}

func saveToElasticsearch(sonarQubeDetail SonarQubeDetail) {
	id := fmt.Sprintf("%s:%d", sonarQubeDetail.Ip, sonarQubeDetail.Port)
	err := elasticsearch.AddData("sonarqube-db", id, sonarQubeDetail)
	if err != nil {
		log.Error("An error occured when adding data to elasticsearch :::", err)
	}
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

func checkDefaultCredential(searchResult shodan.Match, wg *sync.WaitGroup) {
	defer wg.Done()

	req, err := network.PrepareRequest(network.PostRequest, fmt.Sprintf(BASE_URL, searchResult.Ip, searchResult.Port, API_AUTHENTICATION_LOGIN), fmt.Sprintf("login=%s&password=%s", DEFAULT_USER, DEFAULT_PASSWORD))
	if err != nil {
		log.Error("", err)
		return
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		log.Error("", err)
		return
	}

	if statusCode == 200 {
		log.Success(fmt.Sprintf("Default Credential Work - %s:%d", searchResult.Ip, searchResult.Port))
	} else {
		log.Fail(fmt.Sprintf("Default Credential Not Work - %s:%d", searchResult.Ip, searchResult.Port))
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
