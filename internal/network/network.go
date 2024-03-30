package network

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"radar/internal/log"
)

func PrepareRequest(requestMethod RequestMethod, url, payload string) (*http.Request, error) {
	var err error
	var req *http.Request

	switch requestMethod {
	case GetRequest:
		req, err = http.NewRequest("GET", url, nil)
	case PostRequest:
		req, err = http.NewRequest("POST", url, bytes.NewBuffer([]byte(payload)))
	}

	if err != nil {
		log.Stdout(log.Error, "An error occured when preparing request", err.Error())
	}

	return req, err
}

func HostIsAccessible(port int, ip string) (bool, net.Conn) {
	result := false

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), 10 * time.Second)

	if err != nil {
		log.Stdout(log.Warning, fmt.Sprintf("%s:%d - Host Not Accessible", ip, port), err.Error())
	} else if conn == nil {
		log.Stdout(log.Warning, fmt.Sprintf("%s:%d - Connection is NULL", ip, port), "")
	} else {
		result = true
	}

	return result, conn
}

func SendRequest(request *http.Request) ([]byte, int, http.Header, error) {

	client := &http.Client{
		Transport: httpTransport,
		Timeout:   30 * time.Second,

		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	response, err := client.Do(request)
	if err != nil {
		log.Stdout(log.Error, fmt.Sprintf("An error occured when sending request to %s - %s", request.Host, request.URL), err.Error())
		return nil, 0, nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Stdout(log.Error, fmt.Sprintf("An error occured when reading response body belong %s - %s", request.Host, request.URL), err.Error())
		return nil, 0, nil, err
	}

	statusCode := response.StatusCode
	headers := response.Header

	err = response.Body.Close()
	if err != nil {
		log.Stdout(log.Error, fmt.Sprintf("An error occured when closing response body %s - %s", request.Host, request.URL), err.Error())
		return nil, 0, nil, err
	}

	return body, statusCode, headers, err
}
