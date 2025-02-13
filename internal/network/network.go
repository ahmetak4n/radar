package network

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Prepare request with user supplied variables
func PrepareRequest(requestMethod RequestMethod, url, payload string) (*http.Request, error) {
	var err error
	var req *http.Request

	switch requestMethod {
	case GetRequest:
		req, err = http.NewRequest("GET", url, nil)
	case PostRequest:
		req, err = http.NewRequest("POST", url, bytes.NewBuffer([]byte(payload)))
	}

	return req, fmt.Errorf("an error occured while preparing request to %s ::: %w", url, err)
}

// Send reqeust to target
func SendRequest(request *http.Request) ([]byte, int, http.Header, error) {
	var err error

	response, err := client.Do(request)
	if err != nil {
		err = fmt.Errorf("an error occured while sending request to %s - %s ::: %w", request.Host, request.URL, err)
		return nil, 0, nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		err = fmt.Errorf("an error occured while reading response of %s - %s ::: %w", request.Host, request.URL, err)
		return nil, 0, nil, err
	}

	statusCode := response.StatusCode
	headers := response.Header

	err = response.Body.Close()
	if err != nil {
		err = fmt.Errorf("an error occured while closing response body %s - %s ::: %w", request.Host, request.URL, err)
		return nil, 0, nil, err
	}

	return body, statusCode, headers, err
}

// Check target host is accessible or not
func HostConnection(ip string, port int) (net.Conn, error) {
	var err error

	connection, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), 10*time.Second)

	if err != nil {
		err = fmt.Errorf("an error occured while connecting to %s:%d ::: %w", ip, port, err)
	}

	if connection == nil {
		err = fmt.Errorf("an error occured while creating connection to %s:%d", ip, port)
	}

	return connection, err
}
