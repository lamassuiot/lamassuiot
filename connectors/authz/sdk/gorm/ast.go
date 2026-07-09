package gorm

import (
	"sort"
	"strings"

	"gorm.io/gorm"
)

// authzParsed holds the extracted parts of an authz SQL query.
type authzParsed struct {
	fromTable string
	joins     []string
	where     string
}

// compoundJoinKeywords lists JOIN variants in longest-first order so that
// "LEFT JOIN" is claimed before the plain "JOIN" substring inside it.
var compoundJoinKeywords = []string{
	"LEFT OUTER JOIN",
	"RIGHT OUTER JOIN",
	"FULL OUTER JOIN",
	"LEFT JOIN",
	"INNER JOIN",
	"RIGHT JOIN",
	"FULL JOIN",
	"CROSS JOIN",
	"JOIN",
}

// parseAuthzSQL extracts the FROM table, JOIN clauses, and WHERE condition from an
// authz-generated SELECT query.  Expected form:
//
//	SELECT * FROM [schema.]table [LEFT JOIN ... ON ...] [WHERE ...]
func parseAuthzSQL(sql string) authzParsed {
	if sql == "" {
		return authzParsed{}
	}

	upper := strings.ToUpper(sql)

	// Split off the WHERE clause.
	whereOff := findWordPos(upper, "WHERE")
	whereClause := ""
	body := sql
	if whereOff != -1 {
		whereClause = strings.TrimSpace(sql[whereOff+len("WHERE"):])
		body = sql[:whereOff]
	}

	// Find the FROM keyword.
	fromOff := findWordPos(strings.ToUpper(body), "FROM")
	if fromOff == -1 {
		return authzParsed{where: whereClause}
	}

	afterFrom := strings.TrimSpace(body[fromOff+len("FROM"):])
	upperAfterFrom := strings.ToUpper(afterFrom)

	// Locate all JOIN keywords (greedy longest-match, left-to-right).
	joinPositions := findJoinPositions(upperAfterFrom)

	var fromTable string
	var joins []string

	if len(joinPositions) == 0 {
		fromTable = extractTableName(afterFrom)
	} else {
		fromTable = extractTableName(afterFrom[:joinPositions[0]])
		for i, p := range joinPositions {
			end := len(afterFrom)
			if i+1 < len(joinPositions) {
				end = joinPositions[i+1]
			}
			joins = append(joins, strings.TrimSpace(afterFrom[p:end]))
		}
	}

	return authzParsed{
		fromTable: fromTable,
		joins:     joins,
		where:     whereClause,
	}
}

// AddASTToQuery injects the parsed authz JOINs and WHERE condition into tx.
func AddASTToQuery(tx *gorm.DB, parsed authzParsed) *gorm.DB {
	for _, j := range parsed.joins {
		tx = tx.Joins(j)
	}
	if parsed.where != "" {
		tx = tx.Where(parsed.where)
	}
	return tx
}

// findWordPos returns the byte offset of the first word-boundary occurrence of kw
// (which must already be upper-cased) inside the upper-cased string upper, or -1.
func findWordPos(upper, kw string) int {
	kLen := len(kw)
	for i := 0; i <= len(upper)-kLen; i++ {
		if upper[i:i+kLen] != kw {
			continue
		}
		if i > 0 && isIdentChar(upper[i-1]) {
			continue
		}
		if i+kLen < len(upper) && isIdentChar(upper[i+kLen]) {
			continue
		}
		return i
	}
	return -1
}

// findJoinPositions returns the start positions (in upper) of all JOIN keyword
// occurrences, in ascending order.  Longer compound keywords (LEFT JOIN) are
// matched before their shorter suffixes (JOIN) to avoid double-counting.
func findJoinPositions(upper string) []int {
	claimed := make([]bool, len(upper))
	var positions []int

	for _, kw := range compoundJoinKeywords {
		off := 0
		for {
			idx := strings.Index(upper[off:], kw)
			if idx == -1 {
				break
			}
			p := off + idx
			prevOK := p == 0 || !isIdentChar(upper[p-1])
			nextOK := p+len(kw) == len(upper) || !isIdentChar(upper[p+len(kw)])
			if prevOK && nextOK && !claimed[p] {
				positions = append(positions, p)
				for i := p; i < p+len(kw) && i < len(claimed); i++ {
					claimed[i] = true
				}
			}
			off = p + 1
		}
	}

	sort.Ints(positions)
	return positions
}

// extractTableName returns the unqualified table name from a fragment such as
// "schema.table", "schema.table AS alias", or "table".
func extractTableName(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.IndexAny(s, " \t\r\n"); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.LastIndex(s, "."); idx != -1 {
		s = s[idx+1:]
	}
	return s
}

func isIdentChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
}
