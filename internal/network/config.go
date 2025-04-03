package network

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

var netDialer *net.Dialer = &net.Dialer{
	Timeout:   10 * time.Second,
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

	Proxy: http.ProxyFromEnvironment,
}

var client = &http.Client{
	Transport: httpTransport,
	Timeout:   30 * time.Second,

	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}
