package executor

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	xxHash64 "github.com/pierrec/xxHash/xxHash64"
)

func TestBuildClaudeCCHMaterialMatchesOfficialGolden(t *testing.T) {
	signed, err := os.ReadFile("testdata/cch-cc2.1.215.json")
	if err != nil {
		t.Fatal(err)
	}
	signed = bytes.TrimSuffix(signed, []byte("\n"))
	body := bytes.Replace(signed, []byte("cch=c4060;"), []byte("cch=00000;"), 1)
	material, err := buildClaudeCCHMaterial(body)
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprintf("%05x", xxHash64.Checksum(material, claudeCCHSeed)&0xfffff)
	if got != "c4060" {
		t.Fatalf("cch = %q, want official golden %q", got, "c4060")
	}
}

func TestBuildClaudeCCHMaterialUsesRawByteProjection(t *testing.T) {
	body := []byte(" {\n" +
		`"model":"primary",` + "\n" +
		`"fallbacks":["one",{"quoted":"[not]","nested":[1]}],` + "\n" +
		`"messages":[{"role":"user","content":"\u0041"}],` + "\n" +
		`"fallback_credit_token":"route",` + "\n" +
		`"max_tokens":0032000,` + "\n" +
		`"system":[{"text":"x-anthropic-billing-header: cch=00000;"}],` + "\n" +
		`"nested":{"model":"secondary"},"temperature":1e+00` + "\n}")

	got, err := buildClaudeCCHMaterial(body)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(" {\n" +
		`"model":"",` + "\n" +
		"\n" +
		`"messages":[{"role":"user","content":"\u0041"}],` + "\n" +
		"\n" +
		"\n" +
		`"system":[{"text":"x-anthropic-billing-header: cch=00000;"}],` + "\n" +
		`"nested":{"model":""},"temperature":1e+00` + "\n}")
	if !bytes.Equal(got, want) {
		t.Fatalf("material mismatch\nwant: %s\n got: %s", want, got)
	}
}

func TestBuildClaudeCCHMaterialPreservesEquivalentJSONSpelling(t *testing.T) {
	base := []byte(`{"model":"x","messages":[{"content":"A"}],"system":[{"text":"cch=00000"}],"stream":true}`)
	variants := [][]byte{
		[]byte(`{"model":"x", "messages":[{"content":"A"}],"system":[{"text":"cch=00000"}],"stream":true}`),
		[]byte(`{"model":"x","messages":[{"content":"\u0041"}],"system":[{"text":"cch=00000"}],"stream":true}`),
		[]byte(`{"messages":[{"content":"A"}],"model":"x","system":[{"text":"cch=00000"}],"stream":true}`),
		[]byte(`{"model":"x","messages":[{"content":"A"}],"system":[{"text":"cch=00000"}],"stream":true,"stream":true}`),
	}
	baseMaterial, err := buildClaudeCCHMaterial(base)
	if err != nil {
		t.Fatal(err)
	}
	baseHash := xxHash64.Checksum(baseMaterial, claudeCCHSeed) & 0xfffff
	for index, variant := range variants {
		material, errVariant := buildClaudeCCHMaterial(variant)
		if errVariant != nil {
			t.Fatalf("variant %d: %v", index, errVariant)
		}
		if bytes.Equal(material, baseMaterial) {
			t.Fatalf("variant %d was normalized instead of preserving raw bytes", index)
		}
		if gotHash := xxHash64.Checksum(material, claudeCCHSeed) & 0xfffff; gotHash == baseHash {
			t.Fatalf("variant %d unexpectedly retained hash %05x", index, gotHash)
		}
	}
}

func TestProjectClaudeCCHBodyCommaRules(t *testing.T) {
	tests := map[string]struct {
		body string
		want string
	}{
		"prefer trailing comma": {
			body: `{"fallbacks":[],"x":1}`,
			want: `{"x":1}`,
		},
		"otherwise preceding comma": {
			body: `{"x":1,"fallback_credit_token":"route"}`,
			want: `{"x":1}`,
		},
		"whitespace blocks adjacent comma": {
			body: `{"max_tokens":12 ,"x":1}`,
			want: `{ ,"x":1}`,
		},
		"zero digits leaves match untouched": {
			body: `{"max_tokens":-1,"x":1}`,
			want: `{"max_tokens":-1,"x":1}`,
		},
		"search boundary keeps prior comma": {
			body: `{"x":1,"max_tokens":1,"fallbacks":[]}`,
			want: `{"x":1,}`,
		},
		"unclosed first fallbacks blocks later match": {
			body: `{"fallbacks":[0,"fallbacks":[]}`,
			want: `{"fallbacks":[0,"fallbacks":[]}`,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := string(projectClaudeCCHBody([]byte(test.body))); got != test.want {
				t.Fatalf("projection = %q, want %q", got, test.want)
			}
		})
	}
}

func TestProjectClaudeCCHBodyNativeStringBoundaries(t *testing.T) {
	// model and fallback_credit_token stop at the next raw quote, even an
	// escaped one; fallbacks instead understands strings and escaped quotes.
	body := []byte(`{"model":"a\"b","fallback_credit_token":"a\"b","fallbacks":["]","\\\"["],"x":1}`)
	want := []byte(`{"model":""b"b","x":1}`)
	if got := projectClaudeCCHBody(body); !bytes.Equal(got, want) {
		t.Fatalf("projection mismatch\nwant: %s\n got: %s", want, got)
	}
}

func TestProjectClaudeCCHBodyClosingModelQuoteCanStartField(t *testing.T) {
	body := []byte(`AA"model":"unterminated"max_tokens":12`)
	want := []byte(`AA"model":"`)
	if got := projectClaudeCCHBody(body); !bytes.Equal(got, want) {
		t.Fatalf("projection mismatch\nwant: %s\n got: %s", want, got)
	}
}

func TestFindClaudeCCHPlaceholderExactWindow(t *testing.T) {
	prefix := []byte(`{"message":"cch=00000","system":[`)
	body := append(bytes.Clone(prefix), []byte(`{"text":"cch=00000"}]}`)...)
	offset, ok := findClaudeCCHPlaceholder(body)
	if !ok || string(body[offset:offset+5]) != "00000" {
		t.Fatalf("placeholder = (%d, %v)", offset, ok)
	}
	if offset <= bytes.Index(body, []byte(`"system":[`)) {
		t.Fatalf("selected placeholder before system anchor: %d", offset)
	}

	for name, invalid := range map[string][]byte{
		"system spelling":     []byte(`{"system" :[{"text":"cch=00000"}]}`),
		"already signed":      []byte(`{"system":[{"text":"cch=abcde"}]}`),
		"outside 300 bytes":   []byte(`{"system":[` + strings.Repeat("x", 291) + `cch=00000`),
		"placeholder missing": []byte(`{"system":[{}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, found := findClaudeCCHPlaceholder(invalid); found {
				t.Fatal("unexpected placeholder match")
			}
		})
	}
}

func TestBuildClaudeCCHMaterialDoesNotRequireValidJSON(t *testing.T) {
	body := []byte(`not-json "model":"value" "system":[ cch=00000 "max_tokens":12, tail`)
	got, err := buildClaudeCCHMaterial(body)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(`not-json "model":"" "system":[ cch=00000  tail`)
	if !bytes.Equal(got, want) {
		t.Fatalf("material mismatch\nwant: %s\n got: %s", want, got)
	}
}
