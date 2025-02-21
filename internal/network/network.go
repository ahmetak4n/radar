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

	if err != nil {
		err = fmt.Errorf("network.PrepareRequest ::: %w", err)
	}

	return req, err
}

// Send reqeust to target
func SendRequest(request *http.Request) ([]byte, int, http.Header, error) {
	var err error

	response, err := client.Do(request)
	if err != nil {
		err = fmt.Errorf("network.SendRequest ::: client.Do ::: %w", err)
		return nil, 0, nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		err = fmt.Errorf("network.SendRequest ::: io.ReadAll ::: %w", err)
		return nil, 0, nil, err
	}

	statusCode := response.StatusCode
	headers := response.Header

	err = response.Body.Close()
	if err != nil {
		err = fmt.Errorf("network.SendRequest ::: response.Body.Close ::: %w", err)
		return nil, 0, nil, err
	}

	return body, statusCode, headers, err
}

// Check target host is accessible or not
func HostConnection(ip string, port int) (net.Conn, error) {
	var err error

	connection, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), 10*time.Second)
	if err != nil {
		err = fmt.Errorf("network.HostConnection ::: %w", err)
	}

	if connection == nil {
		err = fmt.Errorf("network.HostConnection ::: null.connection ::: %w", err)
	}

	return connection, err
}
