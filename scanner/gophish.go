package scanner

import (
	"flag"
	"fmt"
	"net"

	"net/http"
	"net/url"

	"html"
	"io/ioutil"
	"strings"

	"radar/core"
	"radar/model"
)

var (
	GOPHISH_LOGIN_PATH = "/login?next=%2F"
	GOPHISH_DEFAULT_USER = "admin"
	GOPHISH_DEFAULT_PASSWORD = "gophish"
)

type GophishScanner struct {
	Menu *flag.FlagSet
}

func NewGophishScanner() (*GophishScanner){
	menu := flag.NewFlagSet("gophish", flag.ExitOnError)

	menu.StringVar(&core.SHODAN_API_KEY, "apiKey", "", "shodan api key (*)")

	gophishScanner := &GophishScanner {
		Menu: menu,
	}
	
	return gophishScanner
}

func (gophish GophishScanner) Scan() {
	if core.SHODAN_API_KEY == "" {
		core.WarningLog("Please fill all required parameter!")
		return
	}

	results := core.ShodanSearch("gophish")

	if (len(results.Matches) < 1) {
		core.WarningLog("Shodan can not found any record!")
		return
	} else {
		core.WarningLog(fmt.Sprintf("%d Record Detected", len(results.Matches)))
	}

	for _, result := range results.Matches {
		var conn net.Conn
		status := false
		
		if (gophishPortControl(result)){
			status, conn = core.HostControl(result.Port, result.Ip_str)
		}
	
		if (status) {
			checkGophishkDefaultCredential(result)
			err := conn.Close()

			core.ErrorLog(err, "An error occured when connection closing")
		}
	}
}

func checkGophishkDefaultCredential(searchResult model.SearchResult) {
	protocol := "http://"

	if (searchResult.Ssl.Jarm != "") {
		protocol = "https://"
	}

	gorillaCsrfCookie, gophishCsrfCookie, csrfToken := getGophishCsrfToken(searchResult, protocol)

	req := core.PrepareRequest("POST", fmt.Sprintf("%s%s:%d%s", protocol, searchResult.Ip_str, searchResult.Port, GOPHISH_LOGIN_PATH) , fmt.Sprintf("username=%s&password=%s&csrf_token=%s", GOPHISH_DEFAULT_USER, GOPHISH_DEFAULT_PASSWORD, csrfToken))
	
	req.AddCookie(&http.Cookie{Name: "_gorilla_csrf", Value: gorillaCsrfCookie})
	req.AddCookie(&http.Cookie{Name: "gophish", Value: gophishCsrfCookie})
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0")

	res, err := core.SendRequest(req)

	if (err != nil) {
		return
	}

	_, err = ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	
	core.ErrorLog(err, "An error occured when reading response body")

	if (res.StatusCode == 302) {
		core.SuccessLog(fmt.Sprintf("Default Credential Work - %s:%d", searchResult.Ip_str, searchResult.Port))
	} else {
		core.FailLog(fmt.Sprintf("Default Credential Not Work - %s:%d", searchResult.Ip_str, searchResult.Port))
	}
}

func getGophishCsrfToken(searchResult model.SearchResult, protocol string) (string, string, string){
	req := core.PrepareRequest("GET", fmt.Sprintf("%s%s:%d/", protocol, searchResult.Ip_str, searchResult.Port) , "")
	res, err := core.SendRequest(req)

	if (err != nil) {
		return "", "", ""
	}

	_, err = ioutil.ReadAll(res.Body)
	core.ErrorLog(err, "An error occured when reading response body")
	
	err = res.Body.Close()
	core.ErrorLog(err, "An error occured when closing response body")

	gorillaCsrfCookie := url.QueryEscape(strings.TrimPrefix(strings.Split(res.Header.Get("Set-Cookie"), ";")[0], "_gorilla_csrf="))

	req = core.PrepareRequest("GET", fmt.Sprintf("%s%s:%d%s", protocol, searchResult.Ip_str, searchResult.Port, GOPHISH_LOGIN_PATH) , "")
	req.AddCookie(&http.Cookie{Name: "_gorilla_csrf", Value: gorillaCsrfCookie})
	res, err = core.SendRequest(req)

	if (err != nil) {
		return "", "", ""
	}

	body, err := ioutil.ReadAll(res.Body)
	core.ErrorLog(err, "An error occured when reading response body")

	err = res.Body.Close()
	core.ErrorLog(err, "An error occured when closing response body")

	gophishCsrfCookie := strings.TrimPrefix(strings.Split(res.Header.Get("Set-Cookie"), ";")[0], "gophish=")

	csrfTokenIndex := strings.Index(string(body), "name=\"csrf_token\"")
	
	//CSRF Token include some HTML entities like &#43;
	csrfToken := url.QueryEscape(html.UnescapeString(strings.Split(string(body)[csrfTokenIndex + 25:], "\" />")[0]))

	return gorillaCsrfCookie, gophishCsrfCookie, csrfToken
}

func gophishPortControl(searchResult model.SearchResult) (bool) {
	result := true

	switch searchResult.Port {
	case 25, 135:
		result = false
	default: 
		result = true
	}
	
	return result
}