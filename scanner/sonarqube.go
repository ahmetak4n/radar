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
	}

	for _, result := range results.Matches {
		status, conn := core.HostControl(result.Port, result.Ip_str)
	
		if (status) {
			go func(r model.SearchResult, c net.Conn) {
				defer c.Close()
			
				checkPublicProject(r)
				checkDefaultCredential(r)
			}(result, conn)
		}
	}
}

func checkPublicProject(searchResult model.SearchResult) {
	req := core.PrepareRequest("GET", "http://" + searchResult.Ip_str + ":" + fmt.Sprint(searchResult.Port) + "/api/users/current", "")
	res, err := core.SendRequest(req)

	if (err != nil) {
		return
	}

	_, err = ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	
	core.ErrorLog(err, "An error occured when reading response body")

	if (res.StatusCode == 200) {
		projectCount := getProjectCount(searchResult) 
		core.SuccessLog(fmt.Sprintf("Public Project Accessible! - %s:%d\n[*******] Project Count: %d", searchResult.Ip_str, searchResult.Port, projectCount))
	} else {
		core.FailLog(fmt.Sprintf("Public Project Not Accessible - %s:%d", searchResult.Ip_str, searchResult.Port))
	}
}

func checkDefaultCredential(searchResult model.SearchResult) {
	req := core.PrepareRequest("POST", "http://" + searchResult.Ip_str + ":" + fmt.Sprint(searchResult.Port) + "/api/authentication/login", "login=admin&password=admin")
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

func getProjectCount(searchResult model.SearchResult) (int) {
	req := core.PrepareRequest("GET", "http://" + searchResult.Ip_str + ":" + fmt.Sprint(searchResult.Port) + "/api/components/search_projects", "")
	res, err := core.SendRequest(req)

	if (err != nil) {
		return 0
	}

	body, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	
	core.ErrorLog(err, "An error occured when reading response body")

	result := model.SonarSearchProjects{}
	json.Unmarshal([]byte(body), &result)

	return result.Paging.Total
}