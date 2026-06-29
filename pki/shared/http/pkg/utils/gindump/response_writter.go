package gindump

import (
	"fmt"
	"mime"
	"strings"

	"github.com/gin-gonic/gin"
)

func DumpResponseWriter(res gin.ResponseWriter, showHeaders bool, showBody bool) string {
	headerHiddenFields := make([]string, 0)
	bodyHiddenFields := make([]string, 0)

	var strB strings.Builder

	//dump resp header
	s, err := formatToBeautifulJson(res.Header(), headerHiddenFields)
	if showHeaders {
		if err != nil {
			strB.WriteString(fmt.Sprintf("\nparse resp header err: %s\n", err.Error()))
		} else {
			strB.WriteString("Response-Header:\n")
			strB.WriteString(string(s))
		}
	}

	if showBody {
		bw, ok := res.(*bodyWriter)
		if !ok {
			strB.WriteString("\nbodyWriter was override , can not read bodyCache")
			goto End
		} //dump res body
		if bodyAllowedForStatus(bw.Status()) && bw.bodyCache.Len() > 0 {
			ctGet := res.Header().Get("Content-Type")
			ct, _, err := mime.ParseMediaType(ctGet)
			if err != nil {
				strB.WriteString(fmt.Sprintf("\ncontent-type: %s parse  err \n %s", ctGet, err.Error()))
				goto End
			}
			switch ct {
			case gin.MIMEJSON:
				s, err := beautifyJsonBytes(bw.bodyCache.Bytes(), bodyHiddenFields)
				if err != nil {
					strB.WriteString(fmt.Sprintf("\nparse bodyCache err: %s\n", err.Error()))
					goto End
				}
				strB.WriteString("\nResponse-Body:\n")
				strB.WriteString(string(s))
			case gin.MIMEHTML:
			default:
				strB.WriteString("\nResponse-Body:\n")
				strB.WriteString(bw.bodyCache.String())

			}
		}

	}

End:
	return strB.String()
}
