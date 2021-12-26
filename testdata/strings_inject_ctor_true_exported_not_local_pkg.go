package examplefuzz

// if needed, fill in imports or run 'goimports'
import (
	"io"
	"strings"
	"testing"
	"unicode"

	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_Builder_Cap(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var b *strings.Builder
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&b)
		if b == nil {
			return
		}

		b.Cap()
	})
}

func Fuzz_Builder_Grow(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var b *strings.Builder
		var n int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&b, &n)
		if b == nil {
			return
		}

		b.Grow(n)
	})
}

func Fuzz_Builder_Len(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var b *strings.Builder
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&b)
		if b == nil {
			return
		}

		b.Len()
	})
}

func Fuzz_Builder_Reset(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var b *strings.Builder
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&b)
		if b == nil {
			return
		}

		b.Reset()
	})
}

func Fuzz_Builder_String(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var b *strings.Builder
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&b)
		if b == nil {
			return
		}

		b.String()
	})
}

func Fuzz_Builder_Write(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var b *strings.Builder
		var p []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&b, &p)
		if b == nil {
			return
		}

		b.Write(p)
	})
}

func Fuzz_Builder_WriteByte(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var b *strings.Builder
		var c byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&b, &c)
		if b == nil {
			return
		}

		b.WriteByte(c)
	})
}

func Fuzz_Builder_WriteRune(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var b *strings.Builder
		var r rune
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&b, &r)
		if b == nil {
			return
		}

		b.WriteRune(r)
	})
}

func Fuzz_Builder_WriteString(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var b *strings.Builder
		var s string
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&b, &s)
		if b == nil {
			return
		}

		b.WriteString(s)
	})
}

func Fuzz_Reader_Len(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		r := strings.NewReader(s)
		r.Len()
	})
}

func Fuzz_Reader_Read(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, b []byte) {
		r := strings.NewReader(s)
		r.Read(b)
	})
}

func Fuzz_Reader_ReadAt(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, b []byte, off int64) {
		r := strings.NewReader(s)
		r.ReadAt(b, off)
	})
}

func Fuzz_Reader_ReadByte(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		r := strings.NewReader(s)
		r.ReadByte()
	})
}

func Fuzz_Reader_ReadRune(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		r := strings.NewReader(s)
		r.ReadRune()
	})
}

func Fuzz_Reader_Reset(f *testing.F) {
	f.Fuzz(func(t *testing.T, s1 string, s2 string) {
		r := strings.NewReader(s1)
		r.Reset(s2)
	})
}

func Fuzz_Reader_Seek(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, offset int64, whence int) {
		r := strings.NewReader(s)
		r.Seek(offset, whence)
	})
}

func Fuzz_Reader_Size(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		r := strings.NewReader(s)
		r.Size()
	})
}

func Fuzz_Reader_UnreadByte(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		r := strings.NewReader(s)
		r.UnreadByte()
	})
}

func Fuzz_Reader_UnreadRune(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		r := strings.NewReader(s)
		r.UnreadRune()
	})
}

func Fuzz_Reader_WriteTo(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var s string
		var w io.Writer
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&s, &w)

		r := strings.NewReader(s)
		r.WriteTo(w)
	})
}

func Fuzz_Replacer_Replace(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var oldnew []string
		var s string
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&oldnew, &s)

		r := strings.NewReplacer(oldnew...)
		r.Replace(s)
	})
}

func Fuzz_Replacer_WriteString(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var oldnew []string
		var w io.Writer
		var s string
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&oldnew, &w, &s)

		r := strings.NewReplacer(oldnew...)
		r.WriteString(w, s)
	})
}

func Fuzz_Compare(f *testing.F) {
	f.Fuzz(func(t *testing.T, a string, b string) {
		strings.Compare(a, b)
	})
}

func Fuzz_Contains(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, substr string) {
		strings.Contains(s, substr)
	})
}

func Fuzz_ContainsAny(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, chars string) {
		strings.ContainsAny(s, chars)
	})
}

func Fuzz_ContainsRune(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, r rune) {
		strings.ContainsRune(s, r)
	})
}

func Fuzz_Count(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, substr string) {
		strings.Count(s, substr)
	})
}

func Fuzz_EqualFold(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, t2 string) {
		strings.EqualFold(s, t2)
	})
}

func Fuzz_Fields(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		strings.Fields(s)
	})
}

// skipping Fuzz_FieldsFunc because parameters include unsupported func or chan: func(rune) bool

func Fuzz_HasPrefix(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, prefix string) {
		strings.HasPrefix(s, prefix)
	})
}

func Fuzz_HasSuffix(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, suffix string) {
		strings.HasSuffix(s, suffix)
	})
}

func Fuzz_Index(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, substr string) {
		strings.Index(s, substr)
	})
}

func Fuzz_IndexAny(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, chars string) {
		strings.IndexAny(s, chars)
	})
}

func Fuzz_IndexByte(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, c byte) {
		strings.IndexByte(s, c)
	})
}

// skipping Fuzz_IndexFunc because parameters include unsupported func or chan: func(rune) bool

func Fuzz_IndexRune(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, r rune) {
		strings.IndexRune(s, r)
	})
}

func Fuzz_Join(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var elems []string
		var sep string
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&elems, &sep)

		strings.Join(elems, sep)
	})
}

func Fuzz_LastIndex(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, substr string) {
		strings.LastIndex(s, substr)
	})
}

func Fuzz_LastIndexAny(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, chars string) {
		strings.LastIndexAny(s, chars)
	})
}

func Fuzz_LastIndexByte(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, c byte) {
		strings.LastIndexByte(s, c)
	})
}

// skipping Fuzz_LastIndexFunc because parameters include unsupported func or chan: func(rune) bool

// skipping Fuzz_Map because parameters include unsupported func or chan: func(rune) rune

func Fuzz_NewReader(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		strings.NewReader(s)
	})
}

func Fuzz_NewReplacer(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var oldnew []string
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&oldnew)

		strings.NewReplacer(oldnew...)
	})
}

func Fuzz_Repeat(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, count int) {
		strings.Repeat(s, count)
	})
}

func Fuzz_Replace(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, old string, new string, n int) {
		strings.Replace(s, old, new, n)
	})
}

func Fuzz_ReplaceAll(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, old string, new string) {
		strings.ReplaceAll(s, old, new)
	})
}

func Fuzz_Split(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, sep string) {
		strings.Split(s, sep)
	})
}

func Fuzz_SplitAfter(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, sep string) {
		strings.SplitAfter(s, sep)
	})
}

func Fuzz_SplitAfterN(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, sep string, n int) {
		strings.SplitAfterN(s, sep, n)
	})
}

func Fuzz_SplitN(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, sep string, n int) {
		strings.SplitN(s, sep, n)
	})
}

func Fuzz_Title(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		strings.Title(s)
	})
}

func Fuzz_ToLower(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		strings.ToLower(s)
	})
}

func Fuzz_ToLowerSpecial(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var c unicode.SpecialCase
		var s string
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&c, &s)

		strings.ToLowerSpecial(c, s)
	})
}

func Fuzz_ToTitle(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		strings.ToTitle(s)
	})
}

func Fuzz_ToTitleSpecial(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var c unicode.SpecialCase
		var s string
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&c, &s)

		strings.ToTitleSpecial(c, s)
	})
}

func Fuzz_ToUpper(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		strings.ToUpper(s)
	})
}

func Fuzz_ToUpperSpecial(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var c unicode.SpecialCase
		var s string
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&c, &s)

		strings.ToUpperSpecial(c, s)
	})
}

func Fuzz_ToValidUTF8(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, replacement string) {
		strings.ToValidUTF8(s, replacement)
	})
}

func Fuzz_Trim(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, cutset string) {
		strings.Trim(s, cutset)
	})
}

// skipping Fuzz_TrimFunc because parameters include unsupported func or chan: func(rune) bool

func Fuzz_TrimLeft(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, cutset string) {
		strings.TrimLeft(s, cutset)
	})
}

// skipping Fuzz_TrimLeftFunc because parameters include unsupported func or chan: func(rune) bool

func Fuzz_TrimPrefix(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, prefix string) {
		strings.TrimPrefix(s, prefix)
	})
}

func Fuzz_TrimRight(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, cutset string) {
		strings.TrimRight(s, cutset)
	})
}

// skipping Fuzz_TrimRightFunc because parameters include unsupported func or chan: func(rune) bool

func Fuzz_TrimSpace(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		strings.TrimSpace(s)
	})
}

func Fuzz_TrimSuffix(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string, suffix string) {
		strings.TrimSuffix(s, suffix)
	})
}
