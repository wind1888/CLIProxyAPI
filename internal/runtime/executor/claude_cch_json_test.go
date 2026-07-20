package executor

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	xxHash64 "github.com/pierrec/xxHash/xxHash64"
	"github.com/tidwall/gjson"
)

const testClaudeCCHBillingHeader = "x-anthropic-billing-header: cc_version=2.1.215.abc; cc_entrypoint=sdk-cli; cch=fffff;"

func TestBuildClaudeCCHMaterialMatchesOfficialGolden(t *testing.T) {
	body, err := os.ReadFile("testdata/cch-cc2.1.177.json")
	if err != nil {
		t.Fatal(err)
	}
	billingHeader := gjson.GetBytes(body, "system.0.text").String()
	material, err := buildClaudeCCHMaterial(body, billingHeader)
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprintf("%05x", xxHash64.Checksum(material, claudeCCHSeed)&0xfffff)
	if got != "a82da" {
		t.Fatalf("cch = %q, want official golden %q", got, "a82da")
	}
}

func TestBuildClaudeCCHMaterialMatchesECMAScriptProjection(t *testing.T) {
	body := []byte(` {
  "\u006dodel": "ignored",
  "messages": [{"role":"user","content":"\u4e2d\u003c\/"}],
  "system": [{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.215.abc; cc_entrypoint=sdk-cli; cch=fffff;"}],
  "max_\u0074okens": 1.0,
  "temperature": 1e+02,
  "metadata": {"z":0,"10":"ten","2":"two","a":1},
  "negzero": -0,
  "big": 9007199254740993
} `)

	got, err := buildClaudeCCHMaterial(body, testClaudeCCHBillingHeader)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"model":"","messages":[{"role":"user","content":"中</"}],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.215.abc; cc_entrypoint=sdk-cli; cch=00000;"}],"temperature":100,"metadata":{"2":"two","10":"ten","z":0,"a":1},"negzero":0,"big":9007199254740992}`)
	if !bytes.Equal(got, want) {
		t.Fatalf("material mismatch\nwant: %s\n got: %s", want, got)
	}
}

func TestBuildClaudeCCHMaterialDuplicateProperties(t *testing.T) {
	body := []byte(`{
  "model":"first",
  "model":"second",
  "fallbacks":[1],
  "x":1,
  "fallbacks":[2],
  "fallback_credit_token":"routing",
  "max_tokens":1,
  "system":[{"text":"x-anthropic-billing-header: cc_version=2.1.215.abc; cc_entrypoint=sdk-cli; cch=fffff;"}],
  "messages":[],
  "nested":{"a":1,"\u0061":2}
}`)

	got, err := buildClaudeCCHMaterial(body, testClaudeCCHBillingHeader)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"model":"","x":1,"system":[{"text":"x-anthropic-billing-header: cc_version=2.1.215.abc; cc_entrypoint=sdk-cli; cch=00000;"}],"messages":[],"nested":{"a":2}}`)
	if !bytes.Equal(got, want) {
		t.Fatalf("material mismatch\nwant: %s\n got: %s", want, got)
	}
}

func TestBuildClaudeCCHMaterialECMAScriptPropertyOrder(t *testing.T) {
	body := []byte(`{
  "messages":[],
  "system":[{"text":"x-anthropic-billing-header: cc_version=2.1.215.abc; cc_entrypoint=sdk-cli; cch=fffff;"}],
  "object":{"4294967295":"not-index","01":"leading","10":"ten","2":"two","0":"zero","4294967294":"last-index","-0":"minus"}
}`)

	got, err := buildClaudeCCHMaterial(body, testClaudeCCHBillingHeader)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"messages":[],"system":[{"text":"x-anthropic-billing-header: cc_version=2.1.215.abc; cc_entrypoint=sdk-cli; cch=00000;"}],"object":{"0":"zero","2":"two","10":"ten","4294967294":"last-index","4294967295":"not-index","01":"leading","-0":"minus"},"model":""}`)
	if !bytes.Equal(got, want) {
		t.Fatalf("material mismatch\nwant: %s\n got: %s", want, got)
	}
}

func TestBuildClaudeCCHMaterialECMAScriptStrings(t *testing.T) {
	body := []byte(`{"model":"x","system":[{"text":"x-anthropic-billing-header: cc_version=2.1.215.abc; cc_entrypoint=sdk-cli; cch=fffff;"}],"s":"\u2028\u2029\ud83d\ude00\ud800x\udc00","html":"\u003c\u003e\u0026","slash":"\/"}`)

	got, err := buildClaudeCCHMaterial(body, testClaudeCCHBillingHeader)
	if err != nil {
		t.Fatal(err)
	}
	wantString := "\u2028\u2029😀" + `\ud800x\udc00`
	for _, fragment := range []string{
		`"s":"` + wantString + `"`,
		`"html":"<>&"`,
		`"slash":"/"`,
	} {
		if !bytes.Contains(got, []byte(fragment)) {
			t.Fatalf("material %s does not contain %q", got, fragment)
		}
	}
}

func TestBuildClaudeCCHMaterialECMAScriptNumbers(t *testing.T) {
	body := []byte(`{
  "model":"x",
  "system":[{"text":"x-anthropic-billing-header: cc_version=2.1.215.abc; cc_entrypoint=sdk-cli; cch=fffff;"}],
  "a":1e20,"b":1e21,"c":1e-7,"d":1e-6,"e":-1e400,"f":1e400,"g":-1e-4000
}`)

	got, err := buildClaudeCCHMaterial(body, testClaudeCCHBillingHeader)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		`"a":100000000000000000000`,
		`"b":1e+21`,
		`"c":1e-7`,
		`"d":0.000001`,
		`"e":null`,
		`"f":null`,
		`"g":0`,
	} {
		if !bytes.Contains(got, []byte(fragment)) {
			t.Fatalf("material %s does not contain %q", got, fragment)
		}
	}
}

func TestBuildClaudeCCHMaterialRejectsWrongTarget(t *testing.T) {
	validBody := []byte(`{"model":"x","system":[{"text":"x-anthropic-billing-header: cc_version=2.1.215.abc; cc_entrypoint=sdk-cli; cch=fffff;"}]}`)
	tests := map[string]struct {
		body    []byte
		header  string
		wantErr string
	}{
		"malformed JSON": {
			body:    append(bytes.Clone(validBody), '{'),
			header:  testClaudeCCHBillingHeader,
			wantErr: "trailing data",
		},
		"mismatched header": {
			body:    validBody,
			header:  strings.Replace(testClaudeCCHBillingHeader, "fffff", "00000", 1),
			wantErr: "does not match",
		},
		"missing system": {
			body:    []byte(`{"model":"x"}`),
			header:  testClaudeCCHBillingHeader,
			wantErr: "system[0]",
		},
		"content-only cch": {
			body:    []byte(`{"model":"x","messages":[{"content":"cc_entrypoint=sdk-cli; cch=dead1;"}],"system":[{"text":"ordinary text"}]}`),
			header:  "ordinary text",
			wantErr: "0 signing placeholders",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := buildClaudeCCHMaterial(test.body, test.header)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}
