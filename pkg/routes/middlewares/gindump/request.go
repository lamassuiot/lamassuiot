package gindump

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

func dumpRequest(req *http.Request, showHeaders bool, showBody bool) string {
	headerHiddenFields := make([]string, 0)
	bodyHiddenFields := make([]string, 0)

	var strB strings.Builder

	//dump req header
	s, err := formatToBeautifulJson(req.Header, headerHiddenFields)
	if showHeaders {
		if err != nil {
			strB.WriteString(fmt.Sprintf("\nparse req header err \n" + err.Error()))
		} else {
			strB.WriteString("Request-Header:\n")
			strB.WriteString(string(s))
		}
	}

	if showBody && req.Body != nil {
		buf, err := ioutil.ReadAll(req.Body)
		if err != nil {
			strB.WriteString(fmt.Sprintf("\nread bodyCache err \n %s", err.Error()))
			return strB.String()
		}
		rdr := ioutil.NopCloser(bytes.NewBuffer(buf))
		req.Body = ioutil.NopCloser(bytes.NewBuffer(buf))
		ctGet := req.Header.Get("Content-Type")
		ct, _, err := mime.ParseMediaType(ctGet)
		if err != nil {
			strB.WriteString(fmt.Sprintf("\ncontent_type: %s parse err \n %s", ctGet, err.Error()))
			return strB.String()
		}

		switch ct {
		case gin.MIMEJSON:
			bts, err := ioutil.ReadAll(rdr)
			if err != nil {
				strB.WriteString(fmt.Sprintf("\nread rdr err \n %s", err.Error()))
				return strB.String()
			}

			s, err := beautifyJsonBytes(bts, bodyHiddenFields)
			if err != nil {
				strB.WriteString(fmt.Sprintf("\nparse req body err \n" + err.Error()))
				return strB.String()
			}

			strB.WriteString("\nRequest-Body:\n")
			strB.WriteString(string(s))
		case gin.MIMEPOSTForm:
			bts, err := ioutil.ReadAll(rdr)
			if err != nil {
				strB.WriteString(fmt.Sprintf("\nread rdr err \n %s", err.Error()))
				return strB.String()
			}
			val, err := url.ParseQuery(string(bts))

			s, err := formatToBeautifulJson(val, bodyHiddenFields)
			if err != nil {
				strB.WriteString(fmt.Sprintf("\nparse req body err \n" + err.Error()))
				return strB.String()
			}
			strB.WriteString("\nRequest-Body:\n")
			strB.WriteString(string(s))
		case gin.MIMEMultipartPOSTForm:
		default:
			bts, err := ioutil.ReadAll(rdr)
			if err != nil {
				strB.WriteString(fmt.Sprintf("\nread rdr err \n %s", err.Error()))
				return strB.String()
			}
			strB.WriteString("\nRequest-Body:\n")
			strB.WriteString(string(bts))
		}
	}

	return strB.String()
}
