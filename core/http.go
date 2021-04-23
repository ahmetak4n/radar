package core

import (
	"time"
	"bytes"

	"net"
	"net/http"
	"crypto/tls"
)

var (
	PROXY_STRING = "http://localhost:8090"
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

func SendRequest(request *http.Request) (*http.Response) {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		KeepAlive: 15 * time.Second,
	}

	transport := &http.Transport {
		DisableCompression: true,
		DialContext: dialer.DialContext,

		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},

		TLSHandshakeTimeout: 5 * time.Second,

		DisableKeepAlives: false,

		MaxIdleConns: 100, 
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost: 100,

		IdleConnTimeout: 15 * time.Second,

		WriteBufferSize: 0,
		ReadBufferSize: 0,
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