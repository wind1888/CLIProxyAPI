package executor

import (
	"bytes"
	"fmt"
)

// Claude Code 2.1.216's native cch implementation does not parse or re-encode
// JSON. It projects the exact request bytes with a handful of byte-pattern
// filters, then hashes the projected bytes. Consequently whitespace, property
// order, duplicate properties, escape spelling, and number spelling all remain
// significant.
var (
	claudeCCHSystemPattern              = []byte(`"system":[`)
	claudeCCHPlaceholderPattern         = []byte(`cch=00000`)
	claudeCCHModelPattern               = []byte(`"model":"`)
	claudeCCHFallbacksPattern           = []byte(`"fallbacks":[`)
	claudeCCHFallbackCreditTokenPattern = []byte(`"fallback_credit_token":"`)
	claudeCCHMaxTokensPattern           = []byte(`"max_tokens":`)
)

const claudeCCHSystemSearchWindow = 300

// findClaudeCCHPlaceholder reproduces the native signer's narrow trigger. It
// starts at the first exact `"system":[` occurrence and searches no more than
// 300 bytes from that position for the first exact cch=00000 placeholder.
// The returned offset points to the first of the five zero digits.
func findClaudeCCHPlaceholder(body []byte) (int, bool) {
	systemOffset := bytes.Index(body, claudeCCHSystemPattern)
	if systemOffset < 0 {
		return 0, false
	}
	windowEnd := systemOffset + claudeCCHSystemSearchWindow
	if windowEnd > len(body) {
		windowEnd = len(body)
	}
	placeholderRelative := bytes.Index(body[systemOffset:windowEnd], claudeCCHPlaceholderPattern)
	if placeholderRelative < 0 {
		return 0, false
	}
	return systemOffset + placeholderRelative + len("cch="), true
}

// buildClaudeCCHMaterial returns the native raw-byte projection hashed for
// cch. The body must still contain the zero placeholder; signing patches those
// five bytes only after the hash has been calculated.
func buildClaudeCCHMaterial(body []byte) ([]byte, error) {
	if _, ok := findClaudeCCHPlaceholder(body); !ok {
		return nil, fmt.Errorf("Claude cch native placeholder is missing")
	}
	return projectClaudeCCHBody(body), nil
}

func projectClaudeCCHBody(body []byte) []byte {
	projected := make([]byte, 0, len(body))
	for searchStart := 0; searchStart < len(body); {
		field, hasField := nextClaudeCCHField(body, searchStart)
		modelStart, modelEnd, hasModel := nextClaudeCCHModel(body, searchStart)
		if hasModel && (!hasField || modelStart < field.start) {
			valueStart := modelStart + len(claudeCCHModelPattern)
			projected = append(projected, body[searchStart:valueStart]...)
			searchStart = modelEnd
			continue
		}
		if hasField {
			deleteStart := field.start
			deleteEnd := field.end
			if deleteEnd < len(body) && body[deleteEnd] == ',' {
				deleteEnd++
			} else if field.start > searchStart && body[field.start-1] == ',' {
				deleteStart--
			}
			projected = append(projected, body[searchStart:deleteStart]...)
			searchStart = deleteEnd
			continue
		}
		projected = append(projected, body[searchStart:]...)
		break
	}
	return projected
}

type claudeCCHField struct {
	start int
	end   int
}

func nextClaudeCCHField(body []byte, searchStart int) (claudeCCHField, bool) {
	candidates := make([]claudeCCHField, 0, 3)
	if candidate, ok := nextClaudeCCHFallbacks(body, searchStart); ok {
		candidates = append(candidates, candidate)
	}
	if candidate, ok := nextClaudeCCHFallbackCreditToken(body, searchStart); ok {
		candidates = append(candidates, candidate)
	}
	if candidate, ok := nextClaudeCCHMaxTokens(body, searchStart); ok {
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		return claudeCCHField{}, false
	}
	earliest := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate.start < earliest.start {
			earliest = candidate
		}
	}
	return earliest, true
}

func nextClaudeCCHFallbacks(body []byte, searchStart int) (claudeCCHField, bool) {
	relativeStart := bytes.Index(body[searchStart:], claudeCCHFallbacksPattern)
	if relativeStart < 0 {
		return claudeCCHField{}, false
	}
	start := searchStart + relativeStart
	end, ok := scanClaudeCCHArray(body, start+len(claudeCCHFallbacksPattern)-1)
	return claudeCCHField{start: start, end: end}, ok
}

func nextClaudeCCHFallbackCreditToken(body []byte, searchStart int) (claudeCCHField, bool) {
	relativeStart := bytes.Index(body[searchStart:], claudeCCHFallbackCreditTokenPattern)
	if relativeStart < 0 {
		return claudeCCHField{}, false
	}
	start := searchStart + relativeStart
	valueStart := start + len(claudeCCHFallbackCreditTokenPattern)
	relativeEnd := bytes.IndexByte(body[valueStart:], '"')
	if relativeEnd < 0 {
		return claudeCCHField{}, false
	}
	return claudeCCHField{start: start, end: valueStart + relativeEnd + 1}, true
}

func nextClaudeCCHMaxTokens(body []byte, searchStart int) (claudeCCHField, bool) {
	for cursor := searchStart; cursor < len(body); {
		relativeStart := bytes.Index(body[cursor:], claudeCCHMaxTokensPattern)
		if relativeStart < 0 {
			return claudeCCHField{}, false
		}
		start := cursor + relativeStart
		end := start + len(claudeCCHMaxTokensPattern)
		digitStart := end
		for end < len(body) && body[end] >= '0' && body[end] <= '9' {
			end++
		}
		if end > digitStart {
			return claudeCCHField{start: start, end: end}, true
		}
		cursor = digitStart
	}
	return claudeCCHField{}, false
}

func nextClaudeCCHModel(body []byte, searchStart int) (int, int, bool) {
	relativeStart := bytes.Index(body[searchStart:], claudeCCHModelPattern)
	if relativeStart < 0 {
		return 0, 0, false
	}
	start := searchStart + relativeStart
	valueStart := start + len(claudeCCHModelPattern)
	relativeEnd := bytes.IndexByte(body[valueStart:], '"')
	if relativeEnd < 0 {
		return 0, 0, false
	}
	return start, valueStart + relativeEnd, true
}

// scanClaudeCCHArray balances only square brackets. Brackets inside strings
// are ignored, with backslash escaping the following byte. Object braces are
// deliberately irrelevant because that is how the native filter behaves.
func scanClaudeCCHArray(body []byte, openingBracket int) (int, bool) {
	if openingBracket < 0 || openingBracket >= len(body) || body[openingBracket] != '[' {
		return 0, false
	}
	depth := 0
	inString := false
	for cursor := openingBracket; cursor < len(body); cursor++ {
		current := body[cursor]
		if inString {
			switch current {
			case '\\':
				if cursor+1 < len(body) {
					cursor++
				}
			case '"':
				inString = false
			}
			continue
		}
		switch current {
		case '"':
			inString = true
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return cursor + 1, true
			}
		}
	}
	return 0, false
}
