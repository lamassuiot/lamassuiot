package gindump

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func Dump() gin.HandlerFunc {
	return DumpWithOptions(true, true, true, true, nil)
}

func DumpWithOptions(showReq bool, showResp bool, showBody bool, showHeaders bool, cb func(dumpStr string)) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var strB strings.Builder

		if showReq {
			strB.WriteString(DumpRequest(ctx.Request, showHeaders, showBody))
		}

		ctx.Writer = &bodyWriter{bodyCache: bytes.NewBufferString(""), ResponseWriter: ctx.Writer}
		ctx.Next()

		if showResp {
			strB.WriteString(DumpResponseWriter(ctx.Writer, showHeaders, showBody))
		}

		if cb != nil {
			cb(strB.String())
		} else {
			fmt.Println(strB.String())
		}
	}
}

type bodyWriter struct {
	gin.ResponseWriter
	bodyCache *bytes.Buffer
}

// rewrite Write()
func (w bodyWriter) Write(b []byte) (int, error) {
	w.bodyCache.Write(b)
	return w.ResponseWriter.Write(b)
}

// bodyAllowedForStatus is a copy of http.bodyAllowedForStatus non-exported function.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == http.StatusNoContent:
		return false
	case status == http.StatusNotModified:
		return false
	}
	return true
}
