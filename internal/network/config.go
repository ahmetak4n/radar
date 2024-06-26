package network

import (
	"net/url"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

var PROXYURL func(*http.Request) (*url.URL, error)

var netDialer *net.Dialer = &net.Dialer{
	Timeout:   15 * time.Second,
	KeepAlive: 15 * time.Second,
}

var httpTransport *http.Transport = &http.Transport{
	DialContext: netDialer.DialContext,

	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},

	DisableCompression: false,
	DisableKeepAlives:  false,

	IdleConnTimeout:     10 * time.Second,
	TLSHandshakeTimeout: 10 * time.Second,

	MaxIdleConns:        100,
	MaxConnsPerHost:     10,
	MaxIdleConnsPerHost: 10,

  Proxy: PROXYURL,
}

