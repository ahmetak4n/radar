package scanner

import (
	"fmt"
	"flag"

	"io/ioutil"

	"radar/core"
	"radar/model"
	"github.com/fatih/color"
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

	print(len(results.Matches))

	for i, result := range results.Matches {
		checkPublicProject(i, result)
		checkDefaultCredential(i, result)
	}
}

func checkPublicProject(index int, searchResult model.SearchResult) {
	req := core.PrepareRequest("GET", "http://" + searchResult.Ip_str + ":" + fmt.Sprint(searchResult.Port) + "/api/users/current", "")
	res := core.SendRequest(req)

	_, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	
	core.ErrorLog(err, "An error occured when reading response body")

	if (res.StatusCode == 200) {
		color.Green("[%d]Checked - %s:%d - Public Project Accessible!", index, searchResult.Ip_str, searchResult.Port)
	} else {
		color.Red("[%d]Checked - %s:%d - Public Project Not Accessible", index, searchResult.Ip_str, searchResult.Port)
	}
}

func checkDefaultCredential(index int, searchResult model.SearchResult) {
	req := core.PrepareRequest("POST", "http://" + searchResult.Ip_str + ":" + fmt.Sprint(searchResult.Port) + "/api/authentication/login", "login=admin&password=admin")
	res := core.SendRequest(req)

	_, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	
	core.ErrorLog(err, "An error occured when reading response body")

	if (res.StatusCode == 200) {
		color.Green("[%d]Checked - %s:%d - Default Credential Work", index, searchResult.Ip_str, searchResult.Port)
	} else {
		color.Red("[%d]Checked - %s:%d - Default Credential Not Work", index, searchResult.Ip_str, searchResult.Port)
	}
}