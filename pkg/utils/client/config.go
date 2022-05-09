package client

import "net/url"

type ClientConfiguration struct {
	URL              *url.URL
	AuthMethod       AuthMethod
	AuthMethodConfig interface{}
	CACertificate    string
}
