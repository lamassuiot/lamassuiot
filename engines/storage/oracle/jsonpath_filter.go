package oracle

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"gorm.io/gorm/clause"
)

const maxOracleJSONPathBytes = 32 * 1024

// The API accepts PostgreSQL JSONPath predicates. This parser handles the
// predicate grammar used by Lamassu filters and emits Oracle SQL/JSON filter
// syntax. Unsupported PostgreSQL constructs return an error; they never turn
// into an existence check with different meaning.
type jsonFilterToken struct {
	text string
	kind byte
}

func lexJSONFilter(input string) ([]jsonFilterToken, error) {
	if len(input) == 0 || len(input) > maxOracleJSONPathBytes {
		return nil, fmt.Errorf("invalid JSONPath predicate")
	}
	var tokens []jsonFilterToken
	for i := 0; i < len(input); {
		c := input[i]
		if unicode.IsSpace(rune(c)) {
			i++
			continue
		}
		if c == '"' {
			start := i
			var err error
			i, err = jsonStringEnd(input, i)
			if err != nil {
				return nil, err
			}
			var value string
			if err := json.Unmarshal([]byte(input[start:i]), &value); err != nil {
				return nil, fmt.Errorf("invalid JSONPath string: %w", err)
			}
			tokens = append(tokens, jsonFilterToken{text: value, kind: 's'})
			continue
		}
		if c == '$' || c == '@' {
			start := i
			i++
			for i < len(input) {
				if unicode.IsSpace(rune(input[i])) {
					j := i
					for j < len(input) && unicode.IsSpace(rune(input[j])) {
						j++
					}
					if j < len(input) && input[j] == '?' {
						i = j
						continue
					}
					break
				}
				if input[i] == '.' {
					i++
					if i < len(input) && input[i] == '"' {
						var err error
						i, err = jsonStringEnd(input, i)
						if err != nil {
							return nil, err
						}
						continue
					}
					if i < len(input) && input[i] == '*' {
						i++
						continue
					}
					memberStart := i
					for i < len(input) && (isJSONPathNameByte(input[i])) {
						i++
					}
					if i == start+2 || !isJSONPathNameByte(input[i-1]) {
						return nil, fmt.Errorf("invalid JSONPath member access")
					}
					if i+1 < len(input) && input[i] == '(' && input[i+1] == ')' {
						method := input[memberStart:i]
						if !validOracleItemMethod(method) {
							return nil, fmt.Errorf("unsupported JSONPath item method %q", method)
						}
						i += 2
					}
					continue
				}
				if input[i] == '[' {
					end := strings.IndexByte(input[i:], ']')
					if end < 0 {
						return nil, fmt.Errorf("unterminated JSONPath array step")
					}
					step := input[i+1 : i+end]
					if err := validateArrayStep(step); err != nil {
						return nil, err
					}
					i += end + 1
					continue
				}
				if input[i] == '?' {
					groupStart := i + 1
					for groupStart < len(input) && unicode.IsSpace(rune(input[groupStart])) {
						groupStart++
					}
					if groupStart >= len(input) || input[groupStart] != '(' {
						return nil, fmt.Errorf("invalid JSONPath filter step after %q", input[start:i])
					}
					end, err := jsonFilterGroupEnd(input, groupStart)
					if err != nil {
						return nil, err
					}
					i = end
					continue
				}
				break
			}
			tokens = append(tokens, jsonFilterToken{text: input[start:i], kind: 'p'})
			continue
		}
		if (c >= '0' && c <= '9') || (c == '-' && i+1 < len(input) && input[i+1] >= '0' && input[i+1] <= '9') {
			start := i
			i++
			for i < len(input) && strings.ContainsRune("0123456789.eE+-", rune(input[i])) {
				i++
			}
			if !json.Valid([]byte(input[start:i])) {
				return nil, fmt.Errorf("invalid JSONPath number %q", input[start:i])
			}
			tokens = append(tokens, jsonFilterToken{text: input[start:i], kind: 'n'})
			continue
		}
		if strings.ContainsRune("(),!<>=&|", rune(c)) {
			start := i
			i++
			for i < len(input) && strings.ContainsRune("=!<>&|", rune(c)) && strings.ContainsRune("=!<>&|", rune(input[i])) {
				i++
			}
			tokens = append(tokens, jsonFilterToken{text: input[start:i], kind: 'o'})
			continue
		}
		if unicode.IsLetter(rune(c)) {
			start := i
			for i < len(input) && (unicode.IsLetter(rune(input[i])) || input[i] == '_') {
				i++
			}
			tokens = append(tokens, jsonFilterToken{text: strings.ToLower(input[start:i]), kind: 'w'})
			continue
		}
		return nil, fmt.Errorf("unsupported character %q in JSONPath predicate", c)
	}
	return tokens, nil
}

func jsonFilterGroupEnd(input string, start int) (int, error) {
	if start >= len(input) || input[start] != '(' {
		return 0, fmt.Errorf("invalid JSONPath filter step")
	}
	depth := 0
	for i := start; i < len(input); i++ {
		switch input[i] {
		case '"':
			end, err := jsonStringEnd(input, i)
			if err != nil {
				return 0, err
			}
			i = end - 1
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1, nil
			}
		}
	}
	return 0, fmt.Errorf("unclosed JSONPath filter step")
}

func jsonStringEnd(input string, start int) (int, error) {
	if start >= len(input) || input[start] != '"' {
		return start, fmt.Errorf("invalid JSONPath string")
	}
	for i := start + 1; i < len(input); i++ {
		if input[i] == '\\' {
			i++
			continue
		}
		if input[i] == '"' {
			var value string
			if err := json.Unmarshal([]byte(input[start:i+1]), &value); err != nil {
				return 0, fmt.Errorf("invalid JSONPath string: %w", err)
			}
			return i + 1, nil
		}
	}
	return 0, fmt.Errorf("unterminated JSONPath string")
}

func validateArrayStep(step string) error {
	if step == "*" {
		return nil
	}
	for _, item := range strings.Split(step, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return fmt.Errorf("invalid empty JSONPath array selector")
		}
		if strings.Contains(item, " to ") {
			bounds := strings.Split(item, " to ")
			if len(bounds) != 2 || !validJSONPathIndex(bounds[0]) || !validJSONPathIndex(bounds[1]) {
				return fmt.Errorf("invalid JSONPath array range %q", item)
			}
			continue
		}
		if !validJSONPathIndex(item) {
			return fmt.Errorf("unsupported JSONPath array selector %q", item)
		}
	}
	return nil
}

func validJSONPathIndex(index string) bool {
	if index == "last" {
		return true
	}
	if strings.HasPrefix(index, "last-") {
		return allASCIIDigits(index[5:])
	}
	_, err := strconv.Atoi(index)
	return err == nil
}

func allASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := range value {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func normalizeArrayStep(step string) string {
	parts := strings.Split(step, ",")
	for i := range parts {
		item := strings.TrimSpace(parts[i])
		if strings.Contains(item, " to ") {
			bounds := strings.Split(item, " to ")
			parts[i] = normalizeArrayIndex(strings.TrimSpace(bounds[0])) + " to " + normalizeArrayIndex(strings.TrimSpace(bounds[1]))
		} else {
			parts[i] = normalizeArrayIndex(item)
		}
	}
	return strings.Join(parts, ", ")
}

func normalizeArrayIndex(index string) string {
	value, err := strconv.Atoi(index)
	if err == nil && value < 0 {
		if value == -1 {
			return "last"
		}
		return "last" + strconv.Itoa(value+1)
	}
	return index
}

func isJSONPathNameByte(c byte) bool {
	return c == '_' || c == '-' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func validOracleItemMethod(method string) bool {
	switch strings.ToLower(method) {
	case "size", "type", "number", "string", "boolean", "double":
		return true
	default:
		return false
	}
}

type jsonFilterParser struct {
	tokens []jsonFilterToken
	pos    int
}

type jsonFilterNode interface {
	emit(*jsonFilterCompiler) (string, error)
}
type jsonFilterLogical struct {
	op          string
	left, right jsonFilterNode
}
type jsonFilterNot struct{ child jsonFilterNode }
type jsonFilterSimpleNot struct{ child jsonFilterNode }
type jsonFilterKnownNot struct {
	path          jsonFilterOperand
	child         jsonFilterNode
	requireString bool
	negate        bool
}
type jsonFilterExists struct{ path jsonFilterOperand }
type jsonFilterIn struct {
	value jsonFilterOperand
	items []jsonFilterOperand
}
type jsonFilterHasSubstring struct {
	value   jsonFilterOperand
	subtext jsonFilterOperand
}
type jsonFilterRegex struct {
	value           jsonFilterOperand
	pattern         jsonFilterOperand
	caseInsensitive bool
	quoted          bool
}
type jsonFilterCompare struct {
	left, right jsonFilterOperand
	op          string
}
type jsonFilterOperand struct {
	text string
	kind byte
}

func (p *jsonFilterParser) peek(value string) bool {
	return p.pos < len(p.tokens) && p.tokens[p.pos].text == value
}
func (p *jsonFilterParser) take(value string) bool {
	if !p.peek(value) {
		return false
	}
	p.pos++
	return true
}

func (p *jsonFilterParser) parseOr() (jsonFilterNode, error) {
	node, err := p.parseAnd()
	for err == nil && p.take("||") {
		var right jsonFilterNode
		right, err = p.parseAnd()
		if err == nil {
			node = jsonFilterLogical{op: "||", left: node, right: right}
		}
	}
	return node, err
}
func (p *jsonFilterParser) parseAnd() (jsonFilterNode, error) {
	node, err := p.parseUnary()
	for err == nil && p.take("&&") {
		var right jsonFilterNode
		right, err = p.parseUnary()
		if err == nil {
			node = jsonFilterLogical{op: "&&", left: node, right: right}
		}
	}
	return node, err
}
func (p *jsonFilterParser) parseUnary() (jsonFilterNode, error) {
	if p.take("exists") {
		parenthesized := p.take("(")
		path, err := p.parseOperand()
		if err != nil || path.kind != 'p' {
			return nil, fmt.Errorf("JSONPath exists requires a path operand")
		}
		if parenthesized && !p.take(")") {
			return nil, fmt.Errorf("unclosed JSONPath exists operand")
		}
		return jsonFilterExists{path: path}, nil
	}
	if p.take("!") {
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		if !jsonFilterIsNegatable(child) {
			return nil, fmt.Errorf("JSONPath negation of this expression cannot preserve PostgreSQL unknown semantics")
		}
		return jsonFilterNot{child: child}, nil
	}
	if p.take("(") {
		node, err := p.parseOr()
		if err != nil || !p.take(")") {
			return nil, fmt.Errorf("unclosed JSONPath predicate group")
		}
		return node, nil
	}
	return p.parseComparison()
}

func jsonFilterIsNegatable(node jsonFilterNode) bool {
	switch node := node.(type) {
	case jsonFilterExists:
		return true
	case jsonFilterNot:
		return jsonFilterIsNegatable(node.child)
	case jsonFilterLogical:
		return jsonFilterIsNegatable(node.left) && jsonFilterIsNegatable(node.right)
	case jsonFilterCompare:
		if node.op == "starts with" {
			return node.left.kind == 'p' && node.right.kind == 's'
		}
		return jsonFilterCompareHasOnePath(node.left, node.right) && jsonFilterComparisonOperator(node.op)
	case jsonFilterHasSubstring:
		return node.value.kind == 'p' && node.subtext.kind == 's'
	case jsonFilterRegex:
		return node.value.kind == 'p' && node.pattern.kind == 's'
	case jsonFilterIn:
		if node.value.kind != 'p' || len(node.items) == 0 {
			return false
		}
		for _, item := range node.items {
			if item.kind != 's' && item.kind != 'n' && item.kind != 'b' {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func jsonFilterCompareHasOnePath(left, right jsonFilterOperand) bool {
	return left.kind == 'p' && right.kind != 'p' || right.kind == 'p' && left.kind != 'p'
}

func jsonFilterComparisonOperator(op string) bool {
	switch op {
	case "==", "!=", "<>", "<", "<=", ">", ">=":
		return true
	default:
		return false
	}
}
func (p *jsonFilterParser) parseComparison() (jsonFilterNode, error) {
	left, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	if p.pos >= len(p.tokens) {
		if left.kind != 'p' {
			return nil, fmt.Errorf("JSONPath predicate must produce a boolean")
		}
		return jsonFilterCompare{left: left, right: jsonFilterOperand{text: "true", kind: 'b'}, op: "=="}, nil
	}
	op := p.tokens[p.pos].text
	if op == "starts" && p.pos+1 < len(p.tokens) && p.tokens[p.pos+1].text == "with" {
		op = "starts with"
		p.pos += 2
	} else if op == "has" && p.pos+1 < len(p.tokens) && p.tokens[p.pos+1].text == "substring" {
		op = "has substring"
		p.pos += 2
	} else if op == "like_regex" && p.tokens[p.pos].kind == 'w' {
		p.pos++
	} else if p.tokens[p.pos].kind == 'w' && op == "in" {
		p.pos++
		if !p.take("(") {
			return nil, fmt.Errorf("JSONPath in requires a value list")
		}
		var items []jsonFilterOperand
		for {
			item, err := p.parseOperand()
			if err != nil {
				return nil, err
			}
			items = append(items, item)
			if p.take(")") {
				break
			}
			if !p.take(",") {
				return nil, fmt.Errorf("invalid JSONPath in value list")
			}
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("JSONPath in value list is empty")
		}
		return jsonFilterIn{value: left, items: items}, nil
	} else if p.tokens[p.pos].kind == 'o' && (op == "==" || op == "!=" || op == "<>" || op == "<" || op == "<=" || op == ">" || op == ">=") {
		p.pos++
	} else {
		if left.kind == 'p' {
			return jsonFilterCompare{left: left, right: jsonFilterOperand{text: "true", kind: 'b'}, op: "=="}, nil
		}
		return nil, fmt.Errorf("unsupported JSONPath predicate near %q", op)
	}
	right, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	if (op == "starts with" || op == "has substring") && right.kind != 's' {
		return nil, fmt.Errorf("JSONPath %s requires a string", op)
	}
	if op == "has substring" {
		return jsonFilterHasSubstring{value: left, subtext: right}, nil
	}
	if op == "like_regex" {
		if left.kind != 'p' || right.kind != 's' {
			return nil, fmt.Errorf("JSONPath like_regex requires a path and string pattern")
		}
		caseInsensitive := false
		quoted := false
		multiline := false
		dotall := false
		if p.take("flag") {
			flags, err := p.parseOperand()
			if err != nil || flags.kind != 's' {
				return nil, fmt.Errorf("JSONPath like_regex flags must be a string")
			}
			for _, flag := range flags.text {
				switch flag {
				case 'i':
					caseInsensitive = true
				case 'q':
					quoted = true
				case 'm':
					multiline = true
				case 's':
					dotall = true
				default:
					return nil, fmt.Errorf("JSONPath like_regex flag %q is unsupported", string(flag))
				}
			}
		}
		if !quoted && (multiline || dotall) {
			return nil, fmt.Errorf("JSONPath like_regex flags m and s are unsupported without q")
		}
		return jsonFilterRegex{value: left, pattern: right, caseInsensitive: caseInsensitive, quoted: quoted}, nil
	}
	return jsonFilterCompare{left: left, right: right, op: op}, nil
}
func (p *jsonFilterParser) parseOperand() (jsonFilterOperand, error) {
	if p.pos >= len(p.tokens) {
		return jsonFilterOperand{}, fmt.Errorf("missing JSONPath operand")
	}
	t := p.tokens[p.pos]
	p.pos++
	switch t.kind {
	case 'p', 's', 'n':
		return jsonFilterOperand{text: t.text, kind: t.kind}, nil
	case 'w':
		if t.text == "true" || t.text == "false" || t.text == "null" {
			return jsonFilterOperand{text: t.text, kind: 'b'}, nil
		}
	}
	return jsonFilterOperand{}, fmt.Errorf("invalid JSONPath operand %q", t.text)
}

type jsonFilterCompiler struct {
	values         []any
	numericFormats []string
}

func (c *jsonFilterCompiler) operand(value jsonFilterOperand) (string, error) {
	switch value.kind {
	case 'p':
		return oracleRelativePath(value.text, c)
	case 's':
		// Oracle SQL treats an empty VARCHAR2 bind as NULL. An empty JSON
		// string is a JSON literal, so keep this single safe constant in the
		// path rather than changing its meaning through PASSING.
		if value.text == "" {
			return `""`, nil
		}
		name := fmt.Sprintf("v%d", len(c.values))
		c.values = append(c.values, value.text)
		c.numericFormats = append(c.numericFormats, "")
		return "$" + name, nil
	case 'n':
		number, format, err := oracleJSONNumberBinding(value.text)
		if err != nil {
			return "", err
		}
		name := fmt.Sprintf("v%d", len(c.values))
		c.values = append(c.values, number)
		c.numericFormats = append(c.numericFormats, format)
		return "$" + name, nil
	case 'b':
		return value.text, nil
	default:
		return "", fmt.Errorf("invalid JSONPath operand")
	}
}

// oracleJSONNumberBinding converts a JSON number to an exact decimal
// scientific literal and a matching Oracle NUMBER format. Numeric JSONPath
// operands must stay NUMBER values in PASSING, but Go float64 cannot preserve
// all JSON number digits.
func oracleJSONNumberBinding(input string) (string, string, error) {
	if !json.Valid([]byte(input)) {
		return "", "", fmt.Errorf("invalid JSONPath number %q", input)
	}
	sign := "+"
	if strings.HasPrefix(input, "-") {
		sign = "-"
		input = input[1:]
	}
	mantissa, exponentText, hasExponent := strings.Cut(strings.ToLower(input), "e")
	integer, fraction, hasFraction := strings.Cut(mantissa, ".")
	if !hasFraction {
		fraction = ""
	}
	digits := integer + fraction
	firstNonzero := strings.IndexFunc(digits, func(r rune) bool { return r != '0' })
	if firstNonzero < 0 {
		return "0.0E+000", "FMS9D9EEEE", nil
	}
	exponent := 0
	if hasExponent {
		parsed, err := strconv.Atoi(exponentText)
		if err != nil {
			return "", "", fmt.Errorf("JSONPath number exponent is outside Oracle NUMBER limits")
		}
		exponent = parsed
	}
	exponent += len(integer) - firstNonzero - 1
	significant := strings.TrimRight(digits[firstNonzero:], "0")
	if len(significant) > 38 {
		return "", "", fmt.Errorf("JSONPath numeric literal has %d significant digits; Oracle NUMBER supports at most 38", len(significant))
	}
	if exponent < -130 || exponent > 125 {
		return "", "", fmt.Errorf("JSONPath numeric literal exponent %d is outside Oracle NUMBER limits", exponent)
	}
	decimal := sign + significant[:1] + "."
	if len(significant) == 1 {
		decimal += "0"
	} else {
		decimal += significant[1:]
	}
	decimal += fmt.Sprintf("E%+03d", exponent)
	format := "FMS9D" + strings.Repeat("9", max(1, len(significant)-1)) + "EEEE"
	return decimal, format, nil
}
func (n jsonFilterLogical) emit(c *jsonFilterCompiler) (string, error) {
	a, err := n.left.emit(c)
	if err != nil {
		return "", err
	}
	b, err := n.right.emit(c)
	if err != nil {
		return "", err
	}
	return "(" + a + " " + n.op + " " + b + ")", nil
}
func (n jsonFilterNot) emit(c *jsonFilterCompiler) (string, error) {
	complement, err := jsonFilterComplement(n.child)
	if err != nil {
		return "", err
	}
	return complement.emit(c)
}
func (n jsonFilterSimpleNot) emit(c *jsonFilterCompiler) (string, error) {
	child, err := n.child.emit(c)
	if err != nil {
		return "", err
	}
	return "!(" + child + ")", nil
}
func (n jsonFilterKnownNot) emit(c *jsonFilterCompiler) (string, error) {
	path, err := c.operand(n.path)
	if err != nil {
		return "", err
	}
	child, err := n.child.emit(c)
	if err != nil {
		return "", err
	}
	guards := []string{"exists" + path}
	if n.requireString {
		guards = append(guards, path+`.type() == "string"`)
	}
	if n.negate {
		child = "!(" + child + ")"
	}
	guards = append(guards, child)
	return "(" + strings.Join(guards, " && ") + ")", nil
}
func (n jsonFilterExists) emit(c *jsonFilterCompiler) (string, error) {
	path, err := c.operand(n.path)
	if err != nil {
		return "", err
	}
	return "exists" + path, nil
}

func jsonFilterComplement(node jsonFilterNode) (jsonFilterNode, error) {
	switch node := node.(type) {
	case jsonFilterExists:
		return jsonFilterSimpleNot{child: node}, nil
	case jsonFilterNot:
		return node.child, nil
	case jsonFilterLogical:
		left, err := jsonFilterComplement(node.left)
		if err != nil {
			return nil, err
		}
		right, err := jsonFilterComplement(node.right)
		if err != nil {
			return nil, err
		}
		op := "||"
		if node.op == "||" {
			op = "&&"
		}
		return jsonFilterLogical{op: op, left: left, right: right}, nil
	case jsonFilterCompare:
		if node.op == "starts with" {
			return jsonFilterKnownNot{path: node.left, child: node, requireString: true, negate: true}, nil
		}
		left, right, op := node.left, node.right, node.op
		if left.kind != 'p' {
			left, right = right, left
			op = reverseJSONComparison(op)
		}
		op = invertJSONComparison(op)
		return jsonFilterKnownNot{path: left, child: jsonFilterCompare{left: left, right: right, op: op}}, nil
	case jsonFilterHasSubstring:
		return jsonFilterKnownNot{path: node.value, child: node, requireString: true, negate: true}, nil
	case jsonFilterRegex:
		return jsonFilterKnownNot{path: node.value, child: node, requireString: true, negate: true}, nil
	case jsonFilterIn:
		var complement jsonFilterNode
		for i, item := range node.items {
			part, err := jsonFilterComplement(jsonFilterCompare{left: node.value, right: item, op: "=="})
			if err != nil {
				return nil, err
			}
			if i == 0 {
				complement = part
			} else {
				complement = jsonFilterLogical{op: "&&", left: complement, right: part}
			}
		}
		return complement, nil
	default:
		return nil, fmt.Errorf("JSONPath negation cannot preserve PostgreSQL unknown semantics")
	}
}

func reverseJSONComparison(op string) string {
	switch op {
	case "<":
		return ">"
	case "<=":
		return ">="
	case ">":
		return "<"
	case ">=":
		return "<="
	default:
		return op
	}
}

func invertJSONComparison(op string) string {
	switch op {
	case "==":
		return "!="
	case "!=", "<>":
		return "=="
	case "<":
		return ">="
	case "<=":
		return ">"
	case ">":
		return "<="
	case ">=":
		return "<"
	default:
		return ""
	}
}
func (n jsonFilterIn) emit(c *jsonFilterCompiler) (string, error) {
	items := make([]string, len(n.items))
	for i := range n.items {
		var err error
		items[i], err = (jsonFilterCompare{left: n.value, right: n.items[i], op: "=="}).emit(c)
		if err != nil {
			return "", err
		}
	}
	return "(" + strings.Join(items, " || ") + ")", nil
}
func (n jsonFilterHasSubstring) emit(c *jsonFilterCompiler) (string, error) {
	value, err := c.operand(n.value)
	if err != nil {
		return "", err
	}
	subtext, err := c.operand(n.subtext)
	if err != nil {
		return "", err
	}
	if n.value.kind == 'p' {
		value += ".stringOnly()"
	}
	return value + " has substring " + subtext, nil
}

func (n jsonFilterRegex) emit(c *jsonFilterCompiler) (string, error) {
	value, err := c.operand(n.value)
	if err != nil {
		return "", err
	}
	patternOperand := n.pattern
	if n.quoted && n.caseInsensitive {
		patternOperand.text = escapeOracleRegexLiteral(patternOperand.text)
	}
	pattern, err := c.operand(patternOperand)
	if err != nil {
		return "", err
	}
	if n.quoted && !n.caseInsensitive {
		return value + ".stringOnly() has substring " + pattern, nil
	}
	value += ".stringOnly()"
	operator := "like_regex"
	if n.caseInsensitive {
		operator = "ci_like_regex"
	}
	return value + " " + operator + " " + pattern, nil
}

func escapeOracleRegexLiteral(value string) string {
	var escaped strings.Builder
	for _, r := range value {
		if strings.ContainsRune(`\.^$|?*+()[]{}`, r) {
			escaped.WriteByte('\\')
		}
		escaped.WriteRune(r)
	}
	return escaped.String()
}
func (n jsonFilterCompare) emit(c *jsonFilterCompiler) (string, error) {
	if n.op == "starts with" {
		left, err := c.operand(n.left)
		if err != nil {
			return "", err
		}
		right, err := c.operand(n.right)
		if err != nil {
			return "", err
		}
		if n.left.kind == 'p' {
			left += ".stringOnly()"
		}
		return left + " starts with " + right, nil
	}
	if n.left.kind == 'p' && n.right.kind == 'p' {
		// Oracle SQL/JSON requires the comparison operand types to be known at
		// compile time. PostgreSQL can compare arbitrary JSON values directly,
		// so preserve support for path-to-path comparisons when both paths end
		// in compatible item methods that fix the resulting type. Do not rely on
		// Oracle's implicit casts here: they can change PostgreSQL JSON ordering.
		leftType := oraclePathComparisonType(n.left.text)
		rightType := oraclePathComparisonType(n.right.text)
		if leftType == "" || rightType == "" {
			return "", fmt.Errorf("Oracle JSONPath comparison between two paths requires a type-producing item method on each path")
		}
		if leftType != rightType {
			return "", fmt.Errorf("Oracle JSONPath path comparison requires compatible item method types, got %s and %s", leftType, rightType)
		}
		left, err := c.operand(n.left)
		if err != nil {
			return "", err
		}
		right, err := c.operand(n.right)
		if err != nil {
			return "", err
		}
		return left + " " + n.op + " " + right, nil
	}
	if n.left.kind != 'p' && n.right.kind == 'p' {
		left, right := n.right, n.left
		op := map[string]string{"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!=", "<>": "<>"}[n.op]
		if op == "" {
			return "", fmt.Errorf("unsupported JSONPath comparison %q", n.op)
		}
		return emitPathLiteralCompare(c, left, right, op)
	}
	if n.left.kind == 'p' {
		return emitPathLiteralCompare(c, n.left, n.right, n.op)
	}
	left, err := c.operand(n.left)
	if err != nil {
		return "", err
	}
	right, err := c.operand(n.right)
	if err != nil {
		return "", err
	}
	return left + " " + n.op + " " + right, nil
}

func oraclePathComparisonType(path string) string {
	for _, method := range []struct{ suffix, valueType string }{
		{suffix: ".number()", valueType: "number"},
		{suffix: ".double()", valueType: "double"},
		{suffix: ".string()", valueType: "string"},
		{suffix: ".boolean()", valueType: "boolean"},
		{suffix: ".size()", valueType: "size"},
		{suffix: ".type()", valueType: "type"},
	} {
		if strings.HasSuffix(strings.ToLower(path), method.suffix) {
			return method.valueType
		}
	}
	return ""
}

// PostgreSQL orders JSONB values by type as null < string < number < boolean
// < array < object. Oracle's native JSON order differs, so comparisons against
// a scalar literal explicitly handle cross-type cases and compare values only
// after converting the matching JSON type to its SQL scalar type.
func emitPathLiteralCompare(c *jsonFilterCompiler, path, literal jsonFilterOperand, op string) (string, error) {
	pathSQL, err := c.operand(path)
	if err != nil {
		return "", err
	}
	if literal.kind != 's' && literal.kind != 'n' && literal.kind != 'b' {
		return "", fmt.Errorf("unsupported JSONPath comparison literal")
	}
	literalSQL, err := c.operand(literal)
	if err != nil {
		return "", err
	}
	// A path-ending item method fixes the path's SQL/JSON type. Appending
	// .type() to a method result is invalid Oracle path syntax (and can apply
	// the conversion twice), so compare the typed result directly.
	if methodType := oraclePathComparisonType(path.text); methodType != "" {
		return pathSQL + " " + op + " " + literalSQL, nil
	}
	targetType := jsonFilterLiteralType(literal)
	typeSQL := pathSQL + ".type()"
	// PostgreSQL JSONPath treats unrelated scalar types as incomparable, not
	// ordered by JSONB's B-tree type rank. JSON null is a special false case for
	// inequality with a non-null scalar, so preserve that case explicitly.
	sameType := "(" + typeSQL + ` == "` + targetType + `" && ` + typedJSONPath(pathSQL, targetType) + " " + op + " " + literalSQL + ")"
	if (op == "!=" || op == "<>") && targetType != "null" {
		return "(" + typeSQL + ` == "null" || ` + sameType + ")", nil
	}
	return sameType, nil
}

func jsonFilterLiteralType(literal jsonFilterOperand) string {
	switch literal.kind {
	case 's':
		return "string"
	case 'n':
		return "number"
	case 'b':
		if literal.text == "null" {
			return "null"
		}
		return "boolean"
	default:
		return ""
	}
}

func typedJSONPath(path, jsonType string) string {
	if strings.HasSuffix(path, "."+jsonType+"()") {
		return path
	}
	switch jsonType {
	case "string":
		return path + ".stringOnly()"
	case "number":
		return path + ".numberOnly()"
	case "boolean":
		return path + ".booleanOnly()"
	default:
		return path
	}
}

func oracleRelativePath(path string, c *jsonFilterCompiler) (string, error) {
	if len(path) == 0 || (path[0] != '$' && path[0] != '@') {
		return "", fmt.Errorf("invalid JSONPath operand %q", path)
	}
	var out strings.Builder
	out.WriteByte('@')
	for i := 1; i < len(path); {
		switch path[i] {
		case ' ', '\t', '\r', '\n':
			for i < len(path) && unicode.IsSpace(rune(path[i])) {
				i++
			}
			if i >= len(path) || path[i] != '?' {
				return "", fmt.Errorf("invalid whitespace in JSONPath operand %q", path)
			}
		case '?':
			groupStart := i + 1
			for groupStart < len(path) && unicode.IsSpace(rune(path[groupStart])) {
				groupStart++
			}
			if groupStart >= len(path) || path[groupStart] != '(' {
				return "", fmt.Errorf("invalid JSONPath filter step in %q at byte %d", path, i)
			}
			end, err := jsonFilterGroupEnd(path, groupStart)
			if err != nil {
				return "", err
			}
			tokens, err := lexJSONFilter(path[groupStart+1 : end-1])
			if err != nil {
				return "", err
			}
			parser := jsonFilterParser{tokens: tokens}
			condition, err := parser.parseOr()
			if err != nil || parser.pos != len(tokens) {
				return "", fmt.Errorf("invalid nested JSONPath filter")
			}
			compiled, err := condition.emit(c)
			if err != nil {
				return "", err
			}
			out.WriteString("?(")
			out.WriteString(compiled)
			out.WriteByte(')')
			i = end
		case '.':
			i++
			if i < len(path) && path[i] == '"' {
				end, err := jsonStringEnd(path, i)
				if err != nil {
					return "", err
				}
				out.WriteString(".")
				out.WriteString(path[i:end])
				i = end
				continue
			}
			if i < len(path) && path[i] == '*' {
				out.WriteString(".*")
				i++
				continue
			}
			start := i
			for i < len(path) && isJSONPathNameByte(path[i]) {
				i++
			}
			if start == i {
				return "", fmt.Errorf("invalid JSONPath member in %q", path)
			}
			if i+1 < len(path) && path[i] == '(' && path[i+1] == ')' {
				method := path[start:i]
				if !validOracleItemMethod(method) {
					return "", fmt.Errorf("unsupported JSONPath item method %q", method)
				}
				out.WriteByte('.')
				out.WriteString(strings.ToLower(method))
				out.WriteString("()")
				i += 2
				continue
			}
			out.WriteString(".\"")
			out.WriteString(path[start:i])
			out.WriteByte('"')
		case '[':
			end := strings.IndexByte(path[i:], ']')
			if end < 0 {
				return "", fmt.Errorf("unterminated JSONPath array step")
			}
			step := path[i+1 : i+end]
			if err := validateArrayStep(step); err != nil {
				return "", err
			}
			out.WriteString("[")
			out.WriteString(normalizeArrayStep(step))
			out.WriteByte(']')
			i += end + 1
		default:
			return "", fmt.Errorf("unsupported JSONPath operand %q", path)
		}
	}
	return out.String(), nil
}

type jsonPredicateExpression struct {
	column         clause.Column
	sql            string
	values         []any
	numericFormats []string
}

func (e jsonPredicateExpression) Build(builder clause.Builder) {
	// Bind markers are expanded here, after the SQL/JSON path has been written,
	// so GORM's question-mark placeholder scanner cannot mistake the JSONPath
	// filter operator (`?(`) for a SQL bind.
	parts := strings.Split(e.sql, "\x01")
	for i, part := range parts {
		columns := strings.Split(part, "\x02")
		for j, text := range columns {
			builder.WriteString(text)
			if j < len(columns)-1 {
				builder.WriteQuoted(e.column)
			}
		}
		if i == len(parts)-1 {
			continue
		}
		if i < len(e.numericFormats) && e.numericFormats[i] != "" {
			builder.WriteString("TO_NUMBER(")
		}
		builder.AddVar(builder, e.values[i])
		if i < len(e.numericFormats) && e.numericFormats[i] != "" {
			builder.WriteString(", '")
			builder.WriteString(e.numericFormats[i])
			builder.WriteString("', 'NLS_NUMERIC_CHARACTERS=''.,''')")
		}
	}
}

type jsonSQLPredicate struct {
	sql            string
	values         []any
	numericFormats []string
}

func (c jsonSQLPredicate) and(other jsonSQLPredicate) jsonSQLPredicate {
	return jsonSQLPredicate{sql: "(" + c.sql + " AND " + other.sql + ")", values: append(c.values, other.values...), numericFormats: append(c.numericFormats, other.numericFormats...)}
}

func (c jsonSQLPredicate) or(other jsonSQLPredicate) jsonSQLPredicate {
	return jsonSQLPredicate{sql: "(" + c.sql + " OR " + other.sql + ")", values: append(c.values, other.values...), numericFormats: append(c.numericFormats, other.numericFormats...)}
}

func (c jsonSQLPredicate) not() jsonSQLPredicate {
	return jsonSQLPredicate{sql: "NOT (" + c.sql + ")", values: c.values, numericFormats: c.numericFormats}
}

func jsonExistsSQL(path string, compiler *jsonFilterCompiler) (jsonSQLPredicate, error) {
	if len(path) > maxOracleJSONPathBytes {
		return jsonSQLPredicate{}, fmt.Errorf("compiled Oracle JSONPath predicate exceeds %d bytes", maxOracleJSONPathBytes)
	}
	var sql strings.Builder
	sql.WriteString("JSON_EXISTS(")
	// The column is a trusted repository field and is rendered by GORM below.
	sql.WriteString("\x02")
	sql.WriteString(", '")
	sql.WriteString(strings.ReplaceAll(path, "'", "''"))
	sql.WriteByte('\'')
	for i := range compiler.values {
		if i == 0 {
			sql.WriteString(" PASSING ")
		} else {
			sql.WriteString(", ")
		}
		sql.WriteString("\x01")
		sql.WriteString(fmt.Sprintf(" AS \"v%d\"", i))
	}
	sql.WriteString(" ERROR ON ERROR)")
	return jsonSQLPredicate{sql: sql.String(), values: compiler.values, numericFormats: compiler.numericFormats}, nil
}

func oracleAbsolutePath(path string, compiler *jsonFilterCompiler) (string, error) {
	relative, err := oracleRelativePath(path, compiler)
	if err != nil {
		return "", err
	}
	return "$" + relative[1:], nil
}

// splitFinalPathStep moves the predicate onto the last concrete path step.
// Oracle does not accept a filter immediately after the root item (`$?(...)`).
func splitFinalPathStep(path string) (base, relative string, err error) {
	if len(path) < 2 || path[0] != '$' {
		return "", "", fmt.Errorf("JSONPath predicate requires an absolute path with a terminal step")
	}
	method := ""
	for _, candidate := range []string{"size", "type", "number", "string", "boolean", "double"} {
		suffix := "." + candidate + "()"
		if strings.HasSuffix(strings.ToLower(path), suffix) {
			method = path[len(path)-len(suffix):]
			path = path[:len(path)-len(suffix)]
			break
		}
	}
	last := -1
	for i := 1; i < len(path); {
		switch path[i] {
		case '.':
			last = i
			i++
			if i < len(path) && path[i] == '"' {
				var end int
				end, err = jsonStringEnd(path, i)
				if err != nil {
					return "", "", err
				}
				i = end
			} else {
				for i < len(path) && isJSONPathNameByte(path[i]) {
					i++
				}
			}
		case '[':
			last = i
			end := strings.IndexByte(path[i:], ']')
			if end < 0 {
				return "", "", fmt.Errorf("unterminated JSONPath array step")
			}
			i += end + 1
		case '?':
			// A nested filter already supplies the terminal predicate context.
			return "", "", fmt.Errorf("nested JSONPath filter cannot be extended with another predicate")
		default:
			return "", "", fmt.Errorf("invalid JSONPath terminal step")
		}
	}
	if last < 1 {
		return "", "", fmt.Errorf("JSONPath root predicates require a terminal item method")
	}
	base = path
	relative = "@" + method
	return base, relative, nil
}

func emitRootFilterAtom(node jsonFilterNode, column clause.Column) (jsonSQLPredicate, error) {
	var pathOperand jsonFilterOperand
	switch n := node.(type) {
	case jsonFilterCompare:
		if n.left.kind == 'p' && n.right.kind == 'p' {
			return emitTypedPathComparison(n, column)
		}
		if n.left.kind == 'p' && isRootItemMethod(n.left.text) {
			return emitRootItemMethodComparison(n, n.left, n.right, n.op, column)
		}
		if n.right.kind == 'p' && isRootItemMethod(n.right.text) {
			return emitRootItemMethodComparison(n, n.right, n.left, reverseJSONComparison(n.op), column)
		}
		if n.left.kind == 'p' {
			pathOperand = n.left
		} else if n.right.kind == 'p' {
			pathOperand = n.right
		} else {
			return jsonSQLPredicate{}, fmt.Errorf("JSONPath comparison requires a path operand")
		}
	case jsonFilterIn:
		pathOperand = n.value
	case jsonFilterHasSubstring:
		pathOperand = n.value
	case jsonFilterRegex:
		pathOperand = n.value
	default:
		return jsonSQLPredicate{}, fmt.Errorf("unsupported JSONPath SQL predicate %T", node)
	}
	base, relative, err := splitFinalPathStep(pathOperand.text)
	if err != nil {
		return jsonSQLPredicate{}, err
	}
	rewrite := func(operand jsonFilterOperand) jsonFilterOperand {
		if operand.kind == 'p' && operand.text == pathOperand.text {
			operand.text = relative
		}
		return operand
	}
	switch n := node.(type) {
	case jsonFilterCompare:
		n.left, n.right = rewrite(n.left), rewrite(n.right)
		node = n
	case jsonFilterIn:
		n.value = rewrite(n.value)
		node = n
	case jsonFilterHasSubstring:
		n.value = rewrite(n.value)
		node = n
	case jsonFilterRegex:
		n.value = rewrite(n.value)
		node = n
	}
	compiler := &jsonFilterCompiler{}
	condition, err := node.emit(compiler)
	if err != nil {
		return jsonSQLPredicate{}, err
	}
	return jsonExistsSQL(base+"?("+condition+")", compiler)
}

func isRootItemMethod(path string) bool {
	return strings.HasPrefix(path, "$") && strings.Contains(path, ".") && !strings.Contains(path, "[") && !strings.Contains(path, "?") && strings.HasPrefix(path[strings.LastIndex(path, "."):], ".") && strings.HasSuffix(path, "()") && strings.Count(path, ".") == 1
}

func oracleMethodSQLType(path string) string {
	switch oraclePathComparisonType(path) {
	case "number", "size":
		return "NUMBER"
	case "double":
		return "BINARY_DOUBLE"
	case "boolean":
		return "BOOLEAN"
	case "string", "type":
		return "VARCHAR2(4000)"
	default:
		return ""
	}
}

func oracleSQLOperator(op string) string {
	if op == "==" {
		return "="
	}
	if op == "!=" {
		return "<>"
	}
	return op
}

func jsonValueSQL(path, sqlType string) string {
	return "JSON_VALUE(\x02, '" + strings.ReplaceAll(path, "'", "''") + "' RETURNING " + sqlType + " NULL ON EMPTY NULL ON ERROR)"
}

func emitRootItemMethodComparison(_ jsonFilterCompare, path, literal jsonFilterOperand, op string, column clause.Column) (jsonSQLPredicate, error) {
	if literal.kind == 'p' || literal.kind == 'b' && literal.text == "null" {
		return jsonSQLPredicate{}, fmt.Errorf("unsupported root JSONPath item-method comparison")
	}
	sqlType := oracleMethodSQLType(path.text)
	if sqlType == "" {
		return jsonSQLPredicate{}, fmt.Errorf("unsupported root JSONPath item method")
	}
	pathCompiler := &jsonFilterCompiler{}
	absolutePath, err := oracleAbsolutePath(path.text, pathCompiler)
	if err != nil {
		return jsonSQLPredicate{}, err
	}
	left := jsonValueSQL(absolutePath, sqlType)
	var right string
	var values []any
	var formats []string
	switch literal.kind {
	case 's':
		right = "\x01"
		values = []any{literal.text}
		formats = []string{""}
	case 'n':
		value, format, err := oracleJSONNumberBinding(literal.text)
		if err != nil {
			return jsonSQLPredicate{}, err
		}
		right = "\x01"
		values = []any{value}
		formats = []string{format}
	default:
		return jsonSQLPredicate{}, fmt.Errorf("unsupported root JSONPath comparison literal")
	}
	return jsonSQLPredicate{sql: left + " " + oracleSQLOperator(op) + " " + right, values: values, numericFormats: formats}, nil
}

func emitTypedPathComparison(n jsonFilterCompare, column clause.Column) (jsonSQLPredicate, error) {
	leftType, rightType := oracleMethodSQLType(n.left.text), oracleMethodSQLType(n.right.text)
	if leftType == "" || leftType != rightType {
		return jsonSQLPredicate{}, fmt.Errorf("Oracle JSONPath path comparison requires compatible type-producing item methods")
	}
	leftPath, err := oracleAbsolutePath(n.left.text, &jsonFilterCompiler{})
	if err != nil {
		return jsonSQLPredicate{}, err
	}
	rightPath, err := oracleAbsolutePath(n.right.text, &jsonFilterCompiler{})
	if err != nil {
		return jsonSQLPredicate{}, err
	}
	return jsonSQLPredicate{sql: jsonValueSQL(leftPath, leftType) + " " + oracleSQLOperator(n.op) + " " + jsonValueSQL(rightPath, rightType)}, nil
}

func emitJSONPredicateSQL(node jsonFilterNode, column clause.Column) (jsonSQLPredicate, error) {
	switch n := node.(type) {
	case jsonFilterLogical:
		left, err := emitJSONPredicateSQL(n.left, column)
		if err != nil {
			return jsonSQLPredicate{}, err
		}
		right, err := emitJSONPredicateSQL(n.right, column)
		if err != nil {
			return jsonSQLPredicate{}, err
		}
		if n.op == "&&" {
			return left.and(right), nil
		}
		return left.or(right), nil
	case jsonFilterNot:
		complement, err := jsonFilterComplement(n.child)
		if err != nil {
			return jsonSQLPredicate{}, err
		}
		return emitJSONPredicateSQL(complement, column)
	case jsonFilterSimpleNot:
		child, err := emitJSONPredicateSQL(n.child, column)
		if err != nil {
			return jsonSQLPredicate{}, err
		}
		return child.not(), nil
	case jsonFilterKnownNot:
		pathCompiler := &jsonFilterCompiler{}
		path, err := oracleAbsolutePath(n.path.text, pathCompiler)
		if err != nil {
			return jsonSQLPredicate{}, err
		}
		present, err := jsonExistsSQL(path, pathCompiler)
		if err != nil {
			return jsonSQLPredicate{}, err
		}
		absent := present.not()
		if n.requireString {
			typePath := n.path
			typePath.text += ".type()"
			base, relative, splitErr := splitFinalPathStep(typePath.text)
			if splitErr != nil {
				return jsonSQLPredicate{}, splitErr
			}
			present, err = jsonExistsSQL(base+"?("+relative+` == "string")`, &jsonFilterCompiler{})
			if err != nil {
				return jsonSQLPredicate{}, err
			}
		}
		child, err := emitJSONPredicateSQL(n.child, column)
		if err != nil {
			return jsonSQLPredicate{}, err
		}
		if n.requireString || n.negate {
			child = present.and(child.not())
		}
		return absent.or(child), nil
	case jsonFilterExists:
		compiler := &jsonFilterCompiler{}
		path, err := oracleAbsolutePath(n.path.text, compiler)
		if err != nil {
			return jsonSQLPredicate{}, err
		}
		return jsonExistsSQL(path, compiler)
	default:
		return emitRootFilterAtom(node, column)
	}
}

func compileJSONPredicate(expression string, column clause.Column) (clause.Expression, error) {
	tokens, err := lexJSONFilter(expression)
	if err != nil {
		return nil, err
	}
	p := jsonFilterParser{tokens: tokens}
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(tokens) {
		return nil, fmt.Errorf("unexpected JSONPath token %q", tokens[p.pos].text)
	}
	predicate, err := emitJSONPredicateSQL(root, column)
	if err != nil {
		return nil, err
	}
	if len(predicate.sql) > maxOracleJSONPathBytes*4 {
		return nil, fmt.Errorf("compiled Oracle JSONPath SQL predicate exceeds %d bytes", maxOracleJSONPathBytes*4)
	}
	// Keep column and bind markers opaque to GORM until Build expands them.
	return jsonPredicateExpression{column: column, sql: predicate.sql, values: predicate.values, numericFormats: predicate.numericFormats}, nil
}
