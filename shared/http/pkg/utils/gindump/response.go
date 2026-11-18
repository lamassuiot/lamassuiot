package gindump

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// maxDumpBodySize (1 MiB) caps how much of a response body DumpResponse reads
// into memory. The body is sent by the remote peer, which may be
// user-controlled (e.g. notification webhooks or OIDC discovery endpoints),
// so an unbounded read lets a hostile server exhaust process memory before
// the caller can apply its own limit. Larger bodies are omitted from the dump
// but still reach the caller unchanged.
const maxDumpBodySize = 1 << 20

func DumpResponse(res *http.Response, showHeaders bool, showBody bool) string {
	headerHiddenFields := make([]string, 0)
	bodyHiddenFields := make([]string, 0)

	var strB strings.Builder

	//dump req header
	s, err := formatToBeautifulJson(res.Header, headerHiddenFields)
	if showHeaders {
		if err != nil {
			strB.WriteString(fmt.Sprintf("\nparse resp header err: %s\n", err.Error()))
		} else {
			strB.WriteString("Response-Header:\n")
			strB.WriteString(string(s))
		}
	}

	if showBody {
		// Read at most maxDumpBodySize+1 bytes; the extra byte tells whether
		// the body exceeds the cap without reading the rest of it.
		origBody := res.Body
		bodyBytes, err := io.ReadAll(io.LimitReader(origBody, maxDumpBodySize+1))
		// Hand the caller the full body again: the prefix already read,
		// followed by the unread remainder, closing the original body.
		res.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(bodyBytes), origBody), origBody}

		if err != nil {
			strB.WriteString(fmt.Sprintf("\nparse resp header err: %s\n", err.Error()))
		}
		if len(bodyBytes) > maxDumpBodySize {
			strB.WriteString(fmt.Sprintf("\nResponse-Body: omitted, larger than %d bytes\n", maxDumpBodySize))
			goto End
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
				s, err := beautifyJsonBytes(bodyBytes, bodyHiddenFields)
				if err != nil {
					strB.WriteString(fmt.Sprintf("\nparse bodyCache err: %s\n", err.Error()))
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
