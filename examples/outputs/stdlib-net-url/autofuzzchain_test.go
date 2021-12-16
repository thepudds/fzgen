package urlfuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import (
	"net/url"
	"testing"

	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_ParseRequestURI_Chain(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var rawURL string
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&rawURL)

		target, err := url.ParseRequestURI(rawURL)
		if err != nil {
			return
		}

		steps := []fuzzer.Step{
			fuzzer.Step{
				Name: "Fuzz_URL_EscapedFragment",
				Func: func() string {
					return target.EscapedFragment()
				}},
			fuzzer.Step{
				Name: "Fuzz_URL_EscapedPath",
				Func: func() string {
					return target.EscapedPath()
				}},
			fuzzer.Step{
				Name: "Fuzz_URL_Hostname",
				Func: func() string {
					return target.Hostname()
				}},
			fuzzer.Step{
				Name: "Fuzz_URL_IsAbs",
				Func: func() bool {
					return target.IsAbs()
				}},
			fuzzer.Step{
				Name: "Fuzz_URL_MarshalBinary",
				Func: func() ([]byte, error) {
					return target.MarshalBinary()
				}},
			fuzzer.Step{
				Name: "Fuzz_URL_Parse",
				Func: func(ref string) (*url.URL, error) {
					return target.Parse(ref)
				}},
			fuzzer.Step{
				Name: "Fuzz_URL_Port",
				Func: func() string {
					return target.Port()
				}},
			fuzzer.Step{
				Name: "Fuzz_URL_Query",
				Func: func() url.Values {
					return target.Query()
				}},
			fuzzer.Step{
				Name: "Fuzz_URL_Redacted",
				Func: func() string {
					return target.Redacted()
				}},
			fuzzer.Step{
				Name: "Fuzz_URL_RequestURI",
				Func: func() string {
					return target.RequestURI()
				}},
			fuzzer.Step{
				Name: "Fuzz_URL_ResolveReference",
				Func: func(ref *url.URL) *url.URL {
					if ref == nil {
						return nil
					}
					return target.ResolveReference(ref)
				}},
			fuzzer.Step{
				Name: "Fuzz_URL_String",
				Func: func() string {
					return target.String()
				}},
			fuzzer.Step{
				Name: "Fuzz_URL_UnmarshalBinary",
				Func: func(text []byte) {
					target.UnmarshalBinary(text)
				}},
		}

		// Execute a specific chain of steps, with the count, sequence and arguments controlled by fz.Chain
		fz.Chain(steps)
	})
}
