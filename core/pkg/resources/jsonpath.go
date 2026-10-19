package resources

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	sortJsonKeyRegex   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	sortJsonIndexRegex = regexp.MustCompile(`^[0-9]{1,9}$`)
)

// ParseSortJsonPath parses the simple JSONPath expressions accepted for sorting
// (e.g. "$.foo.bar", "$.tags[0]", "$.items[last].name", "$[0]") into the
// elements of a Postgres #> path. Array indexes become path elements, with
// "last" mapped to -1. Anything else (wildcards, filters, slices, quoted keys...)
// is rejected. Both the API layer and the storage engines rely on it, so a path
// accepted by one is always accepted by the other.
func ParseSortJsonPath(jsonPath string) ([]string, error) {
	errInvalid := fmt.Errorf("invalid json path")
	rest, ok := strings.CutPrefix(jsonPath, "$")
	if !ok || rest == "" {
		return nil, errInvalid
	}

	var keys []string
	for rest != "" {
		switch rest[0] {
		case '.':
			end := strings.IndexAny(rest[1:], ".[")
			if end == -1 {
				end = len(rest) - 1
			}
			key := rest[1 : end+1]
			if !sortJsonKeyRegex.MatchString(key) {
				return nil, errInvalid
			}
			keys = append(keys, key)
			rest = rest[end+1:]
		case '[':
			end := strings.IndexByte(rest, ']')
			if end == -1 {
				return nil, errInvalid
			}
			idx := rest[1:end]
			switch {
			case idx == "last":
				idx = "-1"
			case !sortJsonIndexRegex.MatchString(idx):
				return nil, errInvalid
			}
			keys = append(keys, idx)
			rest = rest[end+1:]
		default:
			return nil, errInvalid
		}
	}
	return keys, nil
}
