package gorm

import (
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	"gorm.io/gorm"
)

func AddASTToQuery(tx *gorm.DB, ast *pg_query.ParseResult, originalSQL string) *gorm.DB {
	if ast == nil || len(ast.Stmts) == 0 {
		return tx
	}

	root := ast.Stmts[0].GetStmt()
	selectStmt := root.GetSelectStmt()
	if selectStmt == nil {
		return tx
	}

	// Find the start of the WHERE clause to use as a global boundary
	whereStart := getLoc(selectStmt.WhereClause)

	// Process FromClause which contains the Join Tree
	for _, fromItem := range selectStmt.FromClause {
		tx = processJoinItem(tx, fromItem, whereStart, originalSQL)
	}

	// Process Where
	if whereStart != -1 {
		kwStart := findKeywordPos(originalSQL, "WHERE", whereStart)
		whereStr := originalSQL[kwStart:]
		cleanWhere := strings.TrimSpace(removeWherePrefix(whereStr))
		tx = tx.Where(cleanWhere)
	}

	return tx
}

func processJoinItem(tx *gorm.DB, node *pg_query.Node, whereStart int32, sql string) *gorm.DB {
	joinExpr := node.GetJoinExpr()
	if joinExpr == nil {
		return tx
	}

	// 1. Recursively process the Left Argument (Larg) first.
	// This drills down to the base table or previous joins.
	if joinExpr.Larg != nil {
		tx = processJoinItem(tx, joinExpr.Larg, whereStart, sql)
	}

	// 2. Process the Right Argument (Rarg) which is the table being joined here.
	if joinExpr.Rarg != nil && joinExpr.Rarg.GetRangeVar() != nil {
		tableLoc := joinExpr.Rarg.GetRangeVar().Location

		// Find the start of THIS join (look for JOIN/LEFT/INNER behind the table location)
		jStart := findKeywordPos(sql, "JOIN", tableLoc)
		if lIdx := findKeywordPos(sql, "LEFT", jStart); lIdx < jStart && lIdx != -1 {
			jStart = lIdx
		} else if iIdx := findKeywordPos(sql, "INNER", jStart); iIdx < jStart && iIdx != -1 {
			jStart = iIdx
		}

		// Calculate the end of THIS join segment.
		// It should end where the NEXT join starts or where the WHERE clause starts.
		jEnd := int32(len(sql))

		// If there is a WHERE clause, that's our absolute limit
		if whereStart != -1 {
			jEnd = findKeywordPos(sql, "WHERE", whereStart)
		}

		// CRITICAL FIX: Look ahead for the next JOIN keyword starting from the table name
		// If another JOIN exists before our current jEnd, we cut the string there.
		nextJoin := findNextJoinPos(sql, tableLoc)
		if nextJoin != -1 && nextJoin < jEnd {
			jEnd = nextJoin
		}

		joinStr := strings.TrimSpace(sql[jStart:jEnd])
		if joinStr != "" {
			tx = tx.Joins(joinStr)
		}
	}

	return tx
}

func getLoc(node *pg_query.Node) int32 {
	if node == nil {
		return -1
	}
	if n := node.GetAExpr(); n != nil {
		return n.Location
	}
	if n := node.GetBoolExpr(); n != nil {
		return n.Location
	}
	if n := node.GetColumnRef(); n != nil {
		return n.Location
	}
	if n := node.GetSubLink(); n != nil {
		return n.Location
	}
	if n := node.GetNullTest(); n != nil {
		return n.Location
	}
	return -1
}

func findKeywordPos(sql string, kw string, beforePos int32) int32 {
	if beforePos <= 0 {
		return beforePos
	}
	sub := strings.ToUpper(sql[:beforePos])
	idx := strings.LastIndex(sub, strings.ToUpper(kw))
	if idx != -1 {
		return int32(idx)
	}
	return beforePos
}

// findNextJoinPos looks forward from the current position to find where the next join starts
func findNextJoinPos(sql string, startPos int32) int32 {
	if int(startPos) >= len(sql) {
		return -1
	}
	upperSql := strings.ToUpper(sql[startPos:])

	// Keywords that signify a new join is starting
	keywords := []string{"LEFT JOIN", "INNER JOIN", "RIGHT JOIN", "JOIN", "FULL JOIN"}

	firstIdx := -1
	for _, kw := range keywords {
		idx := strings.Index(upperSql, kw)
		if idx != -1 {
			if firstIdx == -1 || idx < firstIdx {
				firstIdx = idx
			}
		}
	}

	if firstIdx != -1 {
		return startPos + int32(firstIdx)
	}
	return -1
}

func removeWherePrefix(s string) string {
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "where") {
		return s[5:]
	}
	return s
}
