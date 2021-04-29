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

func HostControl(index, port int, ip string) (bool) {
	timeout := 5 * time.Second
	result := false
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), timeout)

	if (err != nil){
		WarningLog(fmt.Sprintf("[%d]%s:%d - Host Not Accessible", index, ip, port))
	} else if (conn == nil) {
		WarningLog(fmt.Sprintf("[%d]%s:%d - Connection is NULL", index, ip, port))
	} else {
		conn.Close()
		result = true
	}

	return result
}

func SendRequest(request *http.Request) (*http.Response) {

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		KeepAlive: 10 * time.Second,
	}

	transport := &http.Transport {
		DisableCompression: true,
		DialContext: dialer.DialContext,

		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},

		TLSHandshakeTimeout: 5 * time.Second,

		DisableKeepAlives: false,

		IdleConnTimeout: 10 * time.Second,
	}

	client := &http.Client {
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) (error){
			return http.ErrUseLastResponse
		},
	}

	response, err := client.Do(request)

	ErrorLog(err, "An error occured when sending request")

	return response
}