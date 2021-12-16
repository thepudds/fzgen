package strconvfuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import (
	"strconv"
	"testing"

	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_NumError_Error(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var e *strconv.NumError
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&e)
		if e == nil {
			return
		}

		e.Error()
	})
}

func Fuzz_NumError_Unwrap(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var e *strconv.NumError
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&e)
		if e == nil {
			return
		}

		e.Unwrap()
	})
}

func Fuzz_AppendBool(f *testing.F) {
	f.Fuzz(func(t *testing.T, dst []byte, b bool) {
		strconv.AppendBool(dst, b)
	})
}

func Fuzz_AppendFloat(f *testing.F) {
	f.Fuzz(func(t *testing.T, dst []byte, f2 float64, fmt byte, prec int, bitSize int) {
		strconv.AppendFloat(dst, f2, fmt, prec, bitSize)
	})
}

func Fuzz_AppendInt(f *testing.F) {
	f.Fuzz(func(t *testing.T, dst []byte, i int64, base int) {
		strconv.AppendInt(dst, i, base)
	})
}

func Fuzz_AppendQuote(f *testing.F) {
	f.Fuzz(func(t *testing.T, dst []byte, s string) {
		strconv.AppendQuote(dst, s)
	})
}

func Fuzz_AppendQuoteRune(f *testing.F) {
	f.Fuzz(func(t *testing.T, dst []byte, r rune) {
		strconv.AppendQuoteRune(dst, r)
	})
}

func Fuzz_AppendQuoteRuneToASCII(f *testing.F) {
	f.Fuzz(func(t *testing.T, dst []byte, r rune) {
		strconv.AppendQuoteRuneToASCII(dst, r)
	})
}

func Fuzz_AppendQuoteRuneToGraphic(f *testing.F) {
	f.Fuzz(func(t *testing.T, dst []byte, r rune) {
		strconv.AppendQuoteRuneToGraphic(dst, r)
	})
}

func Fuzz_AppendQuoteToASCII(f *testing.F) {
	f.Fuzz(func(t *testing.T, dst []byte, s string) {
		strconv.AppendQuoteToASCII(dst, s)
	})
}

func Fuzz_AppendQuoteToGraphic(f *testing.F) {
	f.Fuzz(func(t *testing.T, dst []byte, s string) {
		strconv.AppendQuoteToGraphic(dst, s)
	})
}

func Fuzz_AppendUint(f *testing.F) {
	f.Fuzz(func(t *testing.T, dst []byte, i uint64, base int) {
		strconv.AppendUint(dst, i, base)
	})
}

func Fuzz_Atoi(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		strconv.Atoi(s)
	})
}

func Fuzz_CanBackquote(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		strconv.CanBackquote(s)
	})
}

func Fuzz_FormatBool(f *testing.F) {
	f.Fuzz(func(t *testing.T, b bool) {
		strconv.FormatBool(b)
	})
}

func Fuzz_FormatComplex(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var c complex128
		var fmt byte
		var prec int
		var bitSize int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&c, &fmt, &prec, &bitSize)

		strconv.FormatComplex(c, fmt, prec, bitSize)
	})
}

func Fuzz_FormatFloat(f *testing.F) {
	f.Fuzz(func(t *testing.T, f1 float64, fmt byte, prec int, bitSize int) {
		strconv.FormatFloat(f1, fmt, prec, bitSize)
	})
}

func Fuzz_FormatInt(f *testing.F) {
	f.Fuzz(func(t *testing.T, i int64, base int) {
		strconv.FormatInt(i, base)
	})
}

func Fuzz_FormatUint(f *testing.F) {
	f.Fuzz(func(t *testing.T, i uint64, base int) {
		strconv.FormatUint(i, base)
	})
}

func Fuzz_IsGraphic(f *testing.F) {
	f.Fuzz(func(t *testing.T, r rune) {
		strconv.IsGraphic(r)
	})
}

func Fuzz_IsPrint(f *testing.F) {
	f.Fuzz(func(t *testing.T, r rune) {
		strconv.IsPrint(r)
	})
}

func Fuzz_Itoa(f *testing.F) {
	f.Fuzz(func(t *testing.T, i int) {
		strconv.Itoa(i)
	})
}

func Fuzz_ParseBool(f *testing.F) {
	f.Fuzz(func(t *testing.T, str string) {
		strconv.ParseBool(str)
	})
}

func Fuzz_ParseComplex(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, bitSize int) {
		strconv.ParseComplex(s, bitSize)
	})
}

func Fuzz_ParseFloat(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, bitSize int) {
		strconv.ParseFloat(s, bitSize)
	})
}

func Fuzz_ParseInt(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, base int, bitSize int) {
		strconv.ParseInt(s, base, bitSize)
	})
}

func Fuzz_ParseUint(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, base int, bitSize int) {
		strconv.ParseUint(s, base, bitSize)
	})
}

func Fuzz_Quote(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		strconv.Quote(s)
	})
}

func Fuzz_QuoteRune(f *testing.F) {
	f.Fuzz(func(t *testing.T, r rune) {
		strconv.QuoteRune(r)
	})
}

func Fuzz_QuoteRuneToASCII(f *testing.F) {
	f.Fuzz(func(t *testing.T, r rune) {
		strconv.QuoteRuneToASCII(r)
	})
}

func Fuzz_QuoteRuneToGraphic(f *testing.F) {
	f.Fuzz(func(t *testing.T, r rune) {
		strconv.QuoteRuneToGraphic(r)
	})
}

func Fuzz_QuoteToASCII(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		strconv.QuoteToASCII(s)
	})
}

func Fuzz_QuoteToGraphic(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		strconv.QuoteToGraphic(s)
	})
}

func Fuzz_QuotedPrefix(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		strconv.QuotedPrefix(s)
	})
}

func Fuzz_Unquote(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		strconv.Unquote(s)
	})
}

func Fuzz_UnquoteChar(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, quote byte) {
		strconv.UnquoteChar(s, quote)
	})
}
