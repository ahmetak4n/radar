package core

import (
	"bytes"
	"fmt"
	"time"

	"net"
	//"net/url"
	"crypto/tls"
	"net/http"

	"io/ioutil"
)

func PrepareRequest(method, uri, payload string) (*http.Request, error) {
	var err error
	var req *http.Request

	switch method {
	case "GET":
		req, err = http.NewRequest(method, uri, nil)
	case "POST":
		req, err = http.NewRequest(method, uri, bytes.NewBuffer([]byte(payload)))
	}

	if err != nil {
		CustomLogger("error", "An error occured when preparing request", err.Error())
	}

	return req, err
}

func HostControl(port int, ip string) (bool, net.Conn) {
	timeout := 5 * time.Second
	result := false
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), timeout)

	if err != nil {
		CustomLogger("warning", fmt.Sprintf("%s:%d - Host Not Accessible", ip, port), "")
	} else if conn == nil {
		CustomLogger("warning", fmt.Sprintf("%s:%d - Connection is NULL", ip, port), "")
	} else {
		result = true
	}

	return result, conn
}

func SendRequest(request *http.Request) ([]byte, int, http.Header, error) {

	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 10 * time.Second,
	}

	transport := &http.Transport{
		DialContext: dialer.DialContext,

		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},

		DisableCompression: true,
		DisableKeepAlives:  false,

		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     15 * time.Second,

		MaxIdleConns:        100,
		MaxConnsPerHost:     10,
		MaxIdleConnsPerHost: 10,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,

		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	//Set proxy for requests will sending
	//If proxy nil or returns a nil *URL, no proxy used
	//proxyURL, _ := url.Parse("http://localhost:8080")
	//transport.Proxy = http.ProxyURL(proxyURL)

	response, err := client.Do(request)
	if err != nil {
		CustomLogger("error", fmt.Sprintf("An error occured when sending request to %s - %s", request.Host, request.URL), err.Error())
		return nil, 0, nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		CustomLogger("error", fmt.Sprintf("An error occured when reading response body belong %s - %s", request.Host, request.URL), err.Error())
		return nil, 0, nil, err
	}

	statusCode := response.StatusCode
	headers := response.Header

	err = response.Body.Close()
	if err != nil {
		CustomLogger("error", fmt.Sprintf("An error occured when closing response body %s - %s", request.Host, request.URL), err.Error())
		return nil, 0, nil, err
	}

	return body, statusCode, headers, err
}
