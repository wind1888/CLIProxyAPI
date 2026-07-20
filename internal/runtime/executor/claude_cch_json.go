package executor

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Claude Code computes cch over a JSON.parse/JSON.stringify-style projection.
// Go's json.Compact is not equivalent: it preserves escape and number lexemes,
// while unmarshalling into a map loses property insertion order. The small JSON
// representation below preserves ECMAScript's relevant semantics without
// changing the actual request body that is sent upstream.

const claudeCCHJSONMaxDepth = 10_000

type claudeCCHJSONKind uint8

const (
	claudeCCHJSONNull claudeCCHJSONKind = iota
	claudeCCHJSONBool
	claudeCCHJSONNumber
	claudeCCHJSONStringKind
	claudeCCHJSONArray
	claudeCCHJSONObject
)

// JavaScript strings are sequences of UTF-16 code units. Keeping code units
// here preserves lone surrogates, which modern JSON.stringify emits as \udxxx.
type claudeCCHJSONString []uint16

type claudeCCHJSONObjectMember struct {
	key   claudeCCHJSONString
	value *claudeCCHJSONValue
}

type claudeCCHJSONValue struct {
	kind    claudeCCHJSONKind
	boolean bool
	number  float64
	string  claudeCCHJSONString
	array   []*claudeCCHJSONValue
	object  []claudeCCHJSONObjectMember
}

type claudeCCHJSONParser struct {
	data []byte
	pos  int
}

// buildClaudeCCHMaterial returns the exact byte projection hashed for cch. It
// parses the body first so only system[0].text can be zeroed, then applies the
// top-level routing-field projection and ECMAScript JSON.stringify semantics.
func buildClaudeCCHMaterial(body []byte, billingHeader string) ([]byte, error) {
	root, err := parseClaudeCCHJSON(body)
	if err != nil {
		return nil, err
	}
	if root.kind != claudeCCHJSONObject {
		return nil, fmt.Errorf("Claude cch body must be a JSON object")
	}

	system, ok := root.objectValue("system")
	if !ok || system.kind != claudeCCHJSONArray || len(system.array) == 0 || system.array[0].kind != claudeCCHJSONObject {
		return nil, fmt.Errorf("Claude cch system[0] billing block is missing")
	}
	textValue, ok := system.array[0].objectValue("text")
	if !ok || textValue.kind != claudeCCHJSONStringKind {
		return nil, fmt.Errorf("Claude cch system[0].text is missing or not text")
	}
	parsedBillingHeader := textValue.string.goString()
	if billingHeader != "" && parsedBillingHeader != billingHeader {
		return nil, fmt.Errorf("Claude cch billing header does not match parsed system[0].text")
	}
	if matches := claudeBillingHeaderCCHPattern.FindAllStringIndex(parsedBillingHeader, -1); len(matches) != 1 {
		return nil, fmt.Errorf("Claude cch billing block contains %d signing placeholders", len(matches))
	}
	unsignedBillingHeader := claudeBillingHeaderCCHPattern.ReplaceAllString(parsedBillingHeader, "${1}00000${2}")
	textValue.string = claudeCCHJSONStringFromGoString(unsignedBillingHeader)

	root.setObjectValue("model", &claudeCCHJSONValue{
		kind:   claudeCCHJSONStringKind,
		string: claudeCCHJSONString{},
	})
	root.deleteObjectValues("fallbacks", "fallback_credit_token", "max_tokens")

	material, err := root.appendJSON(nil, 0)
	if err != nil {
		return nil, fmt.Errorf("stringify Claude cch projection: %w", err)
	}
	return material, nil
}

func parseClaudeCCHJSON(data []byte) (*claudeCCHJSONValue, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("parse Claude cch body: invalid UTF-8")
	}
	p := claudeCCHJSONParser{data: data}
	p.skipWhitespace()
	value, err := p.parseValue(0)
	if err != nil {
		return nil, fmt.Errorf("parse Claude cch body: %w", err)
	}
	p.skipWhitespace()
	if p.pos != len(p.data) {
		return nil, p.errorf("unexpected trailing data")
	}
	return value, nil
}

func (p *claudeCCHJSONParser) parseValue(depth int) (*claudeCCHJSONValue, error) {
	if p.pos >= len(p.data) {
		return nil, p.errorf("unexpected end of JSON")
	}
	switch p.data[p.pos] {
	case 'n':
		if !p.consumeLiteral("null") {
			return nil, p.errorf("invalid literal")
		}
		return &claudeCCHJSONValue{kind: claudeCCHJSONNull}, nil
	case 't':
		if !p.consumeLiteral("true") {
			return nil, p.errorf("invalid literal")
		}
		return &claudeCCHJSONValue{kind: claudeCCHJSONBool, boolean: true}, nil
	case 'f':
		if !p.consumeLiteral("false") {
			return nil, p.errorf("invalid literal")
		}
		return &claudeCCHJSONValue{kind: claudeCCHJSONBool}, nil
	case '"':
		value, err := p.parseString()
		if err != nil {
			return nil, err
		}
		return &claudeCCHJSONValue{kind: claudeCCHJSONStringKind, string: value}, nil
	case '[':
		return p.parseArray(depth)
	case '{':
		return p.parseObject(depth)
	default:
		if p.data[p.pos] == '-' || isClaudeCCHJSONDigit(p.data[p.pos]) {
			return p.parseNumber()
		}
		return nil, p.errorf("unexpected byte %q", p.data[p.pos])
	}
}

func (p *claudeCCHJSONParser) parseArray(depth int) (*claudeCCHJSONValue, error) {
	if depth >= claudeCCHJSONMaxDepth {
		return nil, p.errorf("maximum JSON nesting depth exceeded")
	}
	p.pos++
	p.skipWhitespace()
	result := &claudeCCHJSONValue{kind: claudeCCHJSONArray}
	if p.consumeByte(']') {
		return result, nil
	}
	for {
		p.skipWhitespace()
		value, err := p.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		result.array = append(result.array, value)
		p.skipWhitespace()
		if p.consumeByte(']') {
			return result, nil
		}
		if !p.consumeByte(',') {
			return nil, p.errorf("expected ',' or ']'")
		}
	}
}

func (p *claudeCCHJSONParser) parseObject(depth int) (*claudeCCHJSONValue, error) {
	if depth >= claudeCCHJSONMaxDepth {
		return nil, p.errorf("maximum JSON nesting depth exceeded")
	}
	p.pos++
	p.skipWhitespace()
	result := &claudeCCHJSONValue{kind: claudeCCHJSONObject}
	if p.consumeByte('}') {
		return result, nil
	}

	// JSON.parse keeps the last value for a duplicate property, but assigning
	// that value does not move the property's original insertion position.
	memberIndex := make(map[string]int)
	for {
		p.skipWhitespace()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, p.errorf("expected object property string")
		}
		key, err := p.parseString()
		if err != nil {
			return nil, err
		}
		p.skipWhitespace()
		if !p.consumeByte(':') {
			return nil, p.errorf("expected ':' after object property")
		}
		p.skipWhitespace()
		value, err := p.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		identity := key.identity()
		if index, exists := memberIndex[identity]; exists {
			result.object[index].value = value
		} else {
			memberIndex[identity] = len(result.object)
			result.object = append(result.object, claudeCCHJSONObjectMember{key: key, value: value})
		}
		p.skipWhitespace()
		if p.consumeByte('}') {
			return result, nil
		}
		if !p.consumeByte(',') {
			return nil, p.errorf("expected ',' or '}'")
		}
	}
}

func (p *claudeCCHJSONParser) parseString() (claudeCCHJSONString, error) {
	p.pos++ // opening quote
	result := make(claudeCCHJSONString, 0, 32)
	for p.pos < len(p.data) {
		b := p.data[p.pos]
		switch {
		case b == '"':
			p.pos++
			return result, nil
		case b == '\\':
			p.pos++
			if p.pos >= len(p.data) {
				return nil, p.errorf("unterminated string escape")
			}
			escape := p.data[p.pos]
			p.pos++
			switch escape {
			case '"', '\\', '/':
				result = append(result, uint16(escape))
			case 'b':
				result = append(result, '\b')
			case 'f':
				result = append(result, '\f')
			case 'n':
				result = append(result, '\n')
			case 'r':
				result = append(result, '\r')
			case 't':
				result = append(result, '\t')
			case 'u':
				if p.pos+4 > len(p.data) {
					return nil, p.errorf("short Unicode escape")
				}
				var codeUnit uint16
				for i := 0; i < 4; i++ {
					hex, ok := claudeCCHJSONHexValue(p.data[p.pos+i])
					if !ok {
						return nil, p.errorf("invalid Unicode escape")
					}
					codeUnit = codeUnit<<4 | uint16(hex)
				}
				p.pos += 4
				result = append(result, codeUnit)
			default:
				return nil, p.errorf("invalid string escape \\%c", escape)
			}
		case b < 0x20:
			return nil, p.errorf("unescaped control character in string")
		case b < utf8.RuneSelf:
			result = append(result, uint16(b))
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size == 1 {
				return nil, p.errorf("invalid UTF-8 in string")
			}
			p.pos += size
			if r <= 0xffff {
				result = append(result, uint16(r))
			} else {
				high, low := utf16.EncodeRune(r)
				result = append(result, uint16(high), uint16(low))
			}
		}
	}
	return nil, p.errorf("unterminated string")
}

func (p *claudeCCHJSONParser) parseNumber() (*claudeCCHJSONValue, error) {
	start := p.pos
	if p.consumeByte('-') && p.pos >= len(p.data) {
		return nil, p.errorf("invalid number")
	}
	if p.consumeByte('0') {
		if p.pos < len(p.data) && isClaudeCCHJSONDigit(p.data[p.pos]) {
			return nil, p.errorf("leading zero in number")
		}
	} else {
		if p.pos >= len(p.data) || p.data[p.pos] < '1' || p.data[p.pos] > '9' {
			return nil, p.errorf("invalid number")
		}
		for p.pos < len(p.data) && isClaudeCCHJSONDigit(p.data[p.pos]) {
			p.pos++
		}
	}
	if p.consumeByte('.') {
		fractionStart := p.pos
		for p.pos < len(p.data) && isClaudeCCHJSONDigit(p.data[p.pos]) {
			p.pos++
		}
		if p.pos == fractionStart {
			return nil, p.errorf("number fraction requires a digit")
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		exponentStart := p.pos
		for p.pos < len(p.data) && isClaudeCCHJSONDigit(p.data[p.pos]) {
			p.pos++
		}
		if p.pos == exponentStart {
			return nil, p.errorf("number exponent requires a digit")
		}
	}

	numberText := string(p.data[start:p.pos])
	number, err := strconv.ParseFloat(numberText, 64)
	if err != nil {
		if numberError, ok := err.(*strconv.NumError); !ok || numberError.Err != strconv.ErrRange {
			return nil, p.errorf("invalid number %q", numberText)
		}
		// JSON.parse accepts overflow/underflow and produces +/-Infinity or
		// signed zero; JSON.stringify subsequently serializes those values.
	}
	return &claudeCCHJSONValue{kind: claudeCCHJSONNumber, number: number}, nil
}

func (p *claudeCCHJSONParser) skipWhitespace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}

func (p *claudeCCHJSONParser) consumeByte(want byte) bool {
	if p.pos < len(p.data) && p.data[p.pos] == want {
		p.pos++
		return true
	}
	return false
}

func (p *claudeCCHJSONParser) consumeLiteral(literal string) bool {
	if len(p.data)-p.pos < len(literal) || string(p.data[p.pos:p.pos+len(literal)]) != literal {
		return false
	}
	p.pos += len(literal)
	return true
}

func (p *claudeCCHJSONParser) errorf(format string, args ...any) error {
	return fmt.Errorf("at byte %d: %s", p.pos, fmt.Sprintf(format, args...))
}

func (v *claudeCCHJSONValue) objectValue(name string) (*claudeCCHJSONValue, bool) {
	if v == nil || v.kind != claudeCCHJSONObject {
		return nil, false
	}
	for i := range v.object {
		if v.object[i].key.equalASCII(name) {
			return v.object[i].value, true
		}
	}
	return nil, false
}

func (v *claudeCCHJSONValue) setObjectValue(name string, value *claudeCCHJSONValue) {
	for i := range v.object {
		if v.object[i].key.equalASCII(name) {
			v.object[i].value = value
			return
		}
	}
	v.object = append(v.object, claudeCCHJSONObjectMember{
		key:   claudeCCHJSONStringFromGoString(name),
		value: value,
	})
}

func (v *claudeCCHJSONValue) deleteObjectValues(names ...string) {
	if v == nil || v.kind != claudeCCHJSONObject {
		return
	}
	kept := v.object[:0]
	for i := range v.object {
		remove := false
		for _, name := range names {
			if v.object[i].key.equalASCII(name) {
				remove = true
				break
			}
		}
		if !remove {
			kept = append(kept, v.object[i])
		}
	}
	v.object = kept
}

func (v *claudeCCHJSONValue) appendJSON(dst []byte, depth int) ([]byte, error) {
	if depth > claudeCCHJSONMaxDepth {
		return nil, fmt.Errorf("maximum JSON nesting depth exceeded")
	}
	switch v.kind {
	case claudeCCHJSONNull:
		return append(dst, "null"...), nil
	case claudeCCHJSONBool:
		if v.boolean {
			return append(dst, "true"...), nil
		}
		return append(dst, "false"...), nil
	case claudeCCHJSONNumber:
		return appendClaudeCCHJSONNumber(dst, v.number), nil
	case claudeCCHJSONStringKind:
		return appendClaudeCCHJSONString(dst, v.string), nil
	case claudeCCHJSONArray:
		dst = append(dst, '[')
		for i, item := range v.array {
			if i > 0 {
				dst = append(dst, ',')
			}
			var err error
			dst, err = item.appendJSON(dst, depth+1)
			if err != nil {
				return nil, err
			}
		}
		return append(dst, ']'), nil
	case claudeCCHJSONObject:
		dst = append(dst, '{')
		order := v.ecmaObjectOrder()
		for outputIndex, memberIndex := range order {
			if outputIndex > 0 {
				dst = append(dst, ',')
			}
			member := &v.object[memberIndex]
			dst = appendClaudeCCHJSONString(dst, member.key)
			dst = append(dst, ':')
			var err error
			dst, err = member.value.appendJSON(dst, depth+1)
			if err != nil {
				return nil, err
			}
		}
		return append(dst, '}'), nil
	default:
		return nil, fmt.Errorf("unknown JSON value kind %d", v.kind)
	}
}

func (v *claudeCCHJSONValue) ecmaObjectOrder() []int {
	type indexedMember struct {
		memberIndex int
		arrayIndex  uint32
	}
	indexed := make([]indexedMember, 0)
	ordinary := make([]int, 0, len(v.object))
	for i := range v.object {
		if arrayIndex, ok := v.object[i].key.arrayIndex(); ok {
			indexed = append(indexed, indexedMember{memberIndex: i, arrayIndex: arrayIndex})
		} else {
			ordinary = append(ordinary, i)
		}
	}
	sort.Slice(indexed, func(i, j int) bool {
		return indexed[i].arrayIndex < indexed[j].arrayIndex
	})
	order := make([]int, 0, len(v.object))
	for _, member := range indexed {
		order = append(order, member.memberIndex)
	}
	return append(order, ordinary...)
}

func appendClaudeCCHJSONNumber(dst []byte, number float64) []byte {
	if math.IsNaN(number) || math.IsInf(number, 0) {
		return append(dst, "null"...)
	}
	// JSON.stringify(-0) is "0".
	if number == 0 {
		return append(dst, '0')
	}

	abs := math.Abs(number)
	format := byte('f')
	if abs < 1e-6 || abs >= 1e21 {
		format = 'e'
	}
	start := len(dst)
	dst = strconv.AppendFloat(dst, number, format, -1, 64)
	if format == 'e' {
		// strconv writes e-09; ECMAScript writes e-9. Positive scientific
		// exponents start at 21 and therefore have no leading zero.
		n := len(dst)
		if n-start >= 4 && dst[n-4] == 'e' && dst[n-3] == '-' && dst[n-2] == '0' {
			dst[n-2] = dst[n-1]
			dst = dst[:n-1]
		}
	}
	return dst
}

func appendClaudeCCHJSONString(dst []byte, value claudeCCHJSONString) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(value); i++ {
		codeUnit := value[i]
		switch codeUnit {
		case '"', '\\':
			dst = append(dst, '\\', byte(codeUnit))
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if codeUnit < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hex[codeUnit>>4], hex[codeUnit&0xf])
				continue
			}
			if 0xd800 <= codeUnit && codeUnit <= 0xdbff {
				if i+1 < len(value) && 0xdc00 <= value[i+1] && value[i+1] <= 0xdfff {
					r := utf16.DecodeRune(rune(codeUnit), rune(value[i+1]))
					dst = utf8.AppendRune(dst, r)
					i++
					continue
				}
				dst = append(dst, '\\', 'u', hex[codeUnit>>12], hex[(codeUnit>>8)&0xf], hex[(codeUnit>>4)&0xf], hex[codeUnit&0xf])
				continue
			}
			if 0xdc00 <= codeUnit && codeUnit <= 0xdfff {
				dst = append(dst, '\\', 'u', hex[codeUnit>>12], hex[(codeUnit>>8)&0xf], hex[(codeUnit>>4)&0xf], hex[codeUnit&0xf])
				continue
			}
			dst = utf8.AppendRune(dst, rune(codeUnit))
		}
	}
	return append(dst, '"')
}

func claudeCCHJSONStringFromGoString(value string) claudeCCHJSONString {
	return claudeCCHJSONString(utf16.Encode([]rune(value)))
}

func (s claudeCCHJSONString) goString() string {
	return string(utf16.Decode([]uint16(s)))
}

func (s claudeCCHJSONString) identity() string {
	bytes := make([]byte, len(s)*2)
	for i, codeUnit := range s {
		bytes[i*2] = byte(codeUnit >> 8)
		bytes[i*2+1] = byte(codeUnit)
	}
	return string(bytes)
}

func (s claudeCCHJSONString) equalASCII(value string) bool {
	if len(s) != len(value) {
		return false
	}
	for i := range s {
		if s[i] != uint16(value[i]) || value[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func (s claudeCCHJSONString) arrayIndex() (uint32, bool) {
	if len(s) == 0 || len(s) > 10 {
		return 0, false
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	var value uint64
	for _, codeUnit := range s {
		if codeUnit < '0' || codeUnit > '9' {
			return 0, false
		}
		value = value*10 + uint64(codeUnit-'0')
		if value > math.MaxUint32-1 {
			return 0, false
		}
	}
	return uint32(value), true
}

func isClaudeCCHJSONDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

func claudeCCHJSONHexValue(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}
