package gindump

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func DumpResponse(res *http.Response, showHeaders bool, showBody bool) string {
	headerHiddenFields := make([]string, 0)
	bodyHiddenFields := make([]string, 0)

	var strB strings.Builder

	//dump req header
	s, err := FormatToBeautifulJson(res.Header, headerHiddenFields)
	if showHeaders {
		if err != nil {
			strB.WriteString(fmt.Sprintf("\nparse resp header err \n" + err.Error()))
		} else {
			strB.WriteString("Response-Header:\n")
			strB.WriteString(string(s))
		}
	}

	if showBody {
		bodyBytes, err := io.ReadAll(res.Body)
		//reset the response body to the original unread state
		res.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

		if err != nil {
			strB.WriteString(fmt.Sprintf("\nparse resp header err \n" + err.Error()))
		}
		//dump res body
		if bodyAllowedForStatus(res.StatusCode) && len(bodyBytes) > 0 {
			ctGet := res.Header.Get("Content-Type")
			ct, _, err := mime.ParseMediaType(ctGet)
			if err != nil {
				strB.WriteString(fmt.Sprintf("\ncontent-type: %s parse  err \n %s", ctGet, err.Error()))
				goto End
			}
			switch ct {
			case gin.MIMEJSON:
				s, err := BeautifyJsonBytes(bodyBytes, bodyHiddenFields)
				if err != nil {
					strB.WriteString(fmt.Sprintf("\nparse bodyCache err \n" + err.Error()))
					goto End
				}
				strB.WriteString("\nResponse-Body:\n")

				strB.WriteString(string(s))
			case gin.MIMEHTML:
			default:
				strB.WriteString("\nResponse-Body:\n")
				strB.WriteString(string(bodyBytes))

			}
		}

	}

End:
	return strB.String()

}
