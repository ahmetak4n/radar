package core

import (
	"fmt"
	"time"
	"bytes"

	"net"
	"net/http"
	"crypto/tls"
)

func PrepareRequest(method, uri, payload string) (*http.Request) {
	var err error
	var req *http.Request

	switch method {
	case "GET":
		req, err = http.NewRequest(method, uri, nil)
	case "POST":
		req, err = http.NewRequest(method, uri, bytes.NewBuffer([]byte(payload)))
	}
	
	ErrorLog(err, "An error occured when preparing request")

	return req
}

func HostControl(port int, ip string) (bool, net.Conn) {
	timeout := 5 * time.Second
	result := false
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), timeout)

	if (err != nil){
		WarningLog(fmt.Sprintf("%s:%d - Host Not Accessible", ip, port))
	} else if (conn == nil) {
		WarningLog(fmt.Sprintf("%s:%d - Connection is NULL", ip, port))
	} else {
		result = true
	}

	return result, conn
}

func SendRequest(request *http.Request) (*http.Response, error) {

	dialer := &net.Dialer{
		Timeout: 15 * time.Second,
		KeepAlive: 10 * time.Second,
	}

	transport := &http.Transport {
		DialContext: dialer.DialContext,

		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},

		DisableCompression: true,
		DisableKeepAlives: false,

		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout: 15 * time.Second,

		MaxIdleConns: 100, 
		MaxConnsPerHost: 10,
		MaxIdleConnsPerHost: 10,
	}

	client := &http.Client {
		Transport: transport,
		Timeout: 30 * time.Second,

		CheckRedirect: func(*http.Request, []*http.Request) (error){
			return http.ErrUseLastResponse
		},
	}

	response, err := client.Do(request)

	ErrorLog(err, fmt.Sprintf("An error occured when sending request to %s", request.Host))

	return response, err
}