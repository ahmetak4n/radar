package test

import (
	"fmt"
	"testing"

	"io/ioutil"

	"radar/core"
)

type PrepareRequestTestData struct {
	exceptedMethod	string
	exceptedHost	string
	exceptedScheme	string
	exceptedData	string

	actualMethod	string
	actualHost		string
	actualScheme	string
	actualData		string
}

func TestPrepareRequest(t *testing.T) {
	getData := &PrepareRequestTestData{
		exceptedMethod: "GET",
		exceptedHost: "google.com",
		exceptedScheme: "https",
		exceptedData: "",
	}

	postData := &PrepareRequestTestData{
		exceptedMethod: "POST",
		exceptedHost: "google.com",
		exceptedScheme: "https",
		exceptedData: "param=value",
	}

	PrepareRequest(getData, t)
	PrepareRequest(postData, t)
}


func PrepareRequest(testData *PrepareRequestTestData, t *testing.T) {
	postReq := core.PrepareRequest(testData.exceptedMethod, fmt.Sprintf("%s://%s", testData.exceptedScheme, testData.exceptedHost), testData.exceptedData)

	testData.actualMethod = postReq.Method
	testData.actualHost = postReq.URL.Host
	testData.actualScheme = postReq.URL.Scheme

	if (testData.exceptedMethod == "POST") {
		body, _ := ioutil.ReadAll(postReq.Body)
		defer postReq.Body.Close()

		testData.actualData = string(body)

		if (testData.actualData != testData.exceptedData) {
			t.Errorf("Expected %s request data %s, actual %s", testData.exceptedMethod, testData.actualData, testData.actualData)
		}
	}

	if (testData.actualMethod != testData.exceptedMethod) {
		t.Errorf("Expected %s request method %s, actual %s", testData.exceptedMethod, testData.exceptedMethod, testData.actualMethod)
	}

	if (testData.actualHost != testData.exceptedHost) {
		t.Errorf("Expected %s request host %s, actual %s", testData.exceptedMethod, testData.exceptedHost, testData.actualHost)
	}

	if (testData.actualScheme != testData.exceptedScheme) {
		t.Errorf("Expected %s request scheme %s, actual %s", testData.exceptedMethod, testData.exceptedScheme, testData.actualScheme)
	}
}