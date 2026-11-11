// Package pagination implements the storage providers' common bookmark format.
package pagination

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
)

type Page struct {
	Offset  int
	Limit   int
	Sort    resources.SortOptions
	Filters []resources.FilterOption
}

func New(params *resources.QueryParameters) (Page, error) {
	page := Page{Limit: resources.DefaultPageSize}
	if params == nil {
		return page, nil
	}
	if params.NextBookmark != "" {
		return Decode(params.NextBookmark)
	}
	if params.PageSize > 0 {
		page.Limit = min(params.PageSize, resources.MaxPageSize)
	}
	if params.Sort.SortField != "" {
		page.Sort = params.Sort
		if page.Sort.SortMode == "" {
			page.Sort.SortMode = resources.SortModeAsc
		}
	}
	page.Filters = params.Filters
	return page, nil
}

// Decode preserves the established PostgreSQL bookmark format. SQL-facing
// consumers must validate fields, sort mode, JSON paths and operators again.
func Decode(bookmark string) (Page, error) {
	invalid := fmt.Errorf("not a valid bookmark")
	page := Page{Limit: resources.DefaultPageSize}
	decoded, err := base64.RawURLEncoding.DecodeString(bookmark)
	if err != nil {
		return page, invalid
	}
	for part := range strings.SplitSeq(string(decoded), ";") {
		if part == "" {
			continue
		}
		key, val, ok := strings.Cut(part, ":")
		if !ok {
			return page, invalid
		}
		switch key {
		case "off":
			page.Offset, err = strconv.Atoi(val)
			if err != nil || page.Offset < 0 {
				return page, invalid
			}
		case "lim":
			page.Limit, err = strconv.Atoi(val)
			if err != nil || page.Limit <= 0 {
				return page, invalid
			}
			page.Limit = min(page.Limit, resources.MaxPageSize)
		case "sortM":
			page.Sort.SortMode = resources.SortMode(val)
		case "sortB":
			page.Sort.SortField = val
		case "sortJP":
			jp, err := base64.StdEncoding.DecodeString(val)
			if err != nil {
				return page, invalid
			}
			page.Sort.JsonPathExpr = string(jp)
		case "filter":
			parts := strings.Split(val, "-")
			if len(parts) != 3 {
				return page, invalid
			}
			field, e1 := base64.StdEncoding.DecodeString(parts[0])
			op, e2 := strconv.Atoi(parts[1])
			value, e3 := base64.StdEncoding.DecodeString(parts[2])
			if e1 != nil || e2 != nil || e3 != nil {
				return page, invalid
			}
			page.Filters = append(page.Filters, resources.FilterOption{Field: string(field), FilterOperation: resources.FilterOperation(op), Value: string(value)})
		}
	}
	if page.Sort.SortField == "" || page.Sort.SortMode == "" {
		page.Sort = resources.SortOptions{}
	}
	return page, nil
}

func (p Page) Next() string {
	var b strings.Builder
	fmt.Fprintf(&b, "off:%d;lim:%d;", p.Offset+p.Limit, p.Limit)
	if p.Sort.SortField != "" {
		fmt.Fprintf(&b, "sortM:%s;", p.Sort.SortMode)
		if p.Sort.JsonPathExpr != "" {
			fmt.Fprintf(&b, "sortJP:%s;", base64.StdEncoding.EncodeToString([]byte(p.Sort.JsonPathExpr)))
		}
		fmt.Fprintf(&b, "sortB:%s;", p.Sort.SortField)
	}
	for _, f := range p.Filters {
		fmt.Fprintf(&b, "filter:%s-%d-%s;", base64.StdEncoding.EncodeToString([]byte(f.Field)), f.FilterOperation, base64.StdEncoding.EncodeToString([]byte(f.Value)))
	}
	return base64.RawURLEncoding.EncodeToString([]byte(b.String()))
}
