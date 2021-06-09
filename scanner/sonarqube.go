package scanner

import (
	"fmt"
	"flag"

	"net"

	"io/ioutil"
	"encoding/json"

	"radar/core"
	"radar/model"
)

var (
	SONAR_LOGIN_PATH = "/api/authentication/login"
	SONAR_DEFAULT_USER = "admin"
	SONAR_DEFAULT_PASSWORD = "admin"
	SONAR_PUBLIC_PROJECT_PATH = "/api/users/current"
	SONAR_PROJECT_COUNT_PATH = "/api/components/search_projects"
	SONAR_PROJECT_ISSUE_COUNT_PATH = "/api/issues/search?resolved=false&facets=types&ps=1&additionalFields=_all"
)

type SonarQubeScanner struct {
	Menu *flag.FlagSet
}

func NewSonarQubeScanner() (*SonarQubeScanner){
	menu := flag.NewFlagSet("sonarqube", flag.ExitOnError)

	menu.StringVar(&core.SHODAN_API_KEY, "apiKey", "", "shodan api key (*)")

	sonarQubeScanner := &SonarQubeScanner {
		Menu: menu,
	}
	
	return sonarQubeScanner
}

func (sonarqube SonarQubeScanner) Scan() {
	if core.SHODAN_API_KEY == "" {
		core.WarningLog("Please fill all required parameter!")
		return
	}

	results := core.ShodanSearch("sonarqube")

	if (len(results.Matches) < 1) {
		core.WarningLog("Shodan can not found any record!")
		return
	} else {
		core.WarningLog(fmt.Sprintf("%d Record Detected", len(results.Matches)))
	}

	for _, result := range results.Matches {
		status, conn := core.HostControl(result.Port, result.Ip_str)
	
		if (status) {
			go func(r model.SearchResult, c net.Conn) {
				defer c.Close()
				checkSonarQubePublicProject(r)
				checkSonarQubeDefaultCredential(r)
			}(result, conn)
		}
	}
}

func checkSonarQubePublicProject(searchResult model.SearchResult) {
	req := core.PrepareRequest("GET", fmt.Sprintf("http://%s:%d%s", searchResult.Ip_str, searchResult.Port, SONAR_PUBLIC_PROJECT_PATH) , "")
	res, err := core.SendRequest(req)

	if (err != nil) {
		return
	}

	_, err = ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	
	core.ErrorLog(err, "An error occured when reading response body")

	if (res.StatusCode == 200) {
		projectCount := getSonarQubeProjectCount(searchResult) 

		if (projectCount > 0) {
			codeSmell, vulnerability, bug, securityHotspot := getProjectIssuesCount(searchResult)
			core.SuccessLog(fmt.Sprintf(
					"Public Project Accessible! - %s:%d\n[*******] Project Count: %d, Code Smell: %d, Vulnerability: %d, Bug: %d, Security Hotspot: %d", 
					searchResult.Ip_str, searchResult.Port, projectCount, codeSmell, vulnerability, bug, securityHotspot))
		} else {
			core.SuccessLog(fmt.Sprintf("Public Project Accessible But Empty - %s:%d", searchResult.Ip_str, searchResult.Port))
		}

	} else {
		core.FailLog(fmt.Sprintf("Public Project Not Accessible - %s:%d", searchResult.Ip_str, searchResult.Port))
	}
}

func checkSonarQubeDefaultCredential(searchResult model.SearchResult) {
	req := core.PrepareRequest("POST", fmt.Sprintf("http://%s:%d%s", searchResult.Ip_str, searchResult.Port, SONAR_LOGIN_PATH) , fmt.Sprintf("login=%s&password=%s", SONAR_DEFAULT_USER, SONAR_DEFAULT_PASSWORD))
	res, err := core.SendRequest(req)

	if (err != nil) {
		return
	}

	_, err = ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	
	core.ErrorLog(err, "An error occured when reading response body")

	if (res.StatusCode == 200) {
		core.SuccessLog(fmt.Sprintf("Default Credential Work - %s:%d", searchResult.Ip_str, searchResult.Port))
	} else {
		core.FailLog(fmt.Sprintf("Default Credential Not Work - %s:%d", searchResult.Ip_str, searchResult.Port))
	}
}

func getSonarQubeProjectCount(searchResult model.SearchResult) (int) {
	req := core.PrepareRequest("GET", fmt.Sprintf("http://%s:%d%s", searchResult.Ip_str, searchResult.Port, SONAR_PROJECT_COUNT_PATH), "")
	res, err := core.SendRequest(req)

	if (err != nil) {
		return 0
	}

	body, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	
	core.ErrorLog(err, "An error occured when reading response body")

	result := model.SonarSearchProjects{}
	err = json.Unmarshal([]byte(body), &result)
	
	core.ErrorLog(err, "An error occured when deserialize object")

	return result.Paging.Total
}

func getProjectIssuesCount(searchResult model.SearchResult) (int, int, int, int) {
	codeSmell, vulnerability, bug, securityHotspot := 0, 0, 0, 0
	
	req := core.PrepareRequest("GET", fmt.Sprintf("http://%s:%d%s", searchResult.Ip_str, searchResult.Port, SONAR_PROJECT_ISSUE_COUNT_PATH), "")
	res, err := core.SendRequest(req)

	if (err != nil) {
		return 0, 0, 0, 0
	}

	body, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	
	core.ErrorLog(err, "An error occured when reading response body")

	result := model.SonarSearchIssues{}

	err = json.Unmarshal([]byte(body), &result)

	core.ErrorLog(err, "An error occured when deserialize object")

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

	return codeSmell, vulnerability, bug, securityHotspot
}