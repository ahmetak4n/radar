package network

import (
	"bytes"
	"errors"
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
		err = errors.New("PrepareRequest ::: An error occured while preparing request ::: " + err.Error())
	}

	return req, err
}

// Send reqeust to target
func SendRequest(request *http.Request) ([]byte, int, http.Header, error) {
	var err error

	response, err := client.Do(request)
	if err != nil {
		err = errors.New(fmt.Sprintf("SendRequest ::: An error occured while sending request to %s - %s ::: %s", request.Host, request.URL, err.Error()))
		return nil, 0, nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		err = errors.New(fmt.Sprintf("SendRequest ::: An error occured while reading response of %s - %s ::: %s", request.Host, request.URL, err.Error()))
		return nil, 0, nil, err
	}

	statusCode := response.StatusCode
	headers := response.Header

	err = response.Body.Close()
	if err != nil {
		err = errors.New(fmt.Sprintf("SendRequest ::: An error occured while closing response %s - %s ::: %s", request.Host, request.URL, err.Error()))
		return nil, 0, nil, err
	}

	return body, statusCode, headers, err
}

// Check target host is accessible or not
func HostConnection(ip string, port int) (net.Conn, error) {
	var err error

	connection, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), 10*time.Second)

	if err != nil {
		err = errors.New(fmt.Sprintf("HostConnection ::: %s:%d - Host Not Accessible ::: %s", ip, port, err.Error()))
	}

	if connection == nil {
		err = errors.New(fmt.Sprintf("HostConnection ::: %s:%d - Connection is Null", ip, port))
	}

	return connection, err
}
