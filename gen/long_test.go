// +build go1.13

package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestStrings(t *testing.T) {
	if testing.Short() {
		// TODO: probably remove this test at some point?
		// It is long, and sensitive to changes in stdlib strings pkg.
		t.Skip("skipping test in short mode. also, currently relies on strings package from Go 1.13")
	}
	tests := []struct {
		name               string
		onlyExported       bool
		qualifyAll         bool
		insertConstructors bool
		want               string
	}{
		{
			name:               "strings: exported only, not local pkg",
			onlyExported:       true,
			qualifyAll:         true,
			insertConstructors: true,
			want: `package stringsfuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import (
	"io"
	"strings"
	"unicode"
)

func Fuzz_Builder_Cap(b *strings.Builder) {
	if b == nil {
		return
	}
	b.Cap()
}

func Fuzz_Builder_Grow(b *strings.Builder, n int) {
	if b == nil {
		return
	}
	b.Grow(n)
}

func Fuzz_Builder_Len(b *strings.Builder) {
	if b == nil {
		return
	}
	b.Len()
}

func Fuzz_Builder_Reset(b *strings.Builder) {
	if b == nil {
		return
	}
	b.Reset()
}

func Fuzz_Builder_String(b *strings.Builder) {
	if b == nil {
		return
	}
	b.String()
}

func Fuzz_Builder_Write(b *strings.Builder, p []byte) {
	if b == nil {
		return
	}
	b.Write(p)
}

func Fuzz_Builder_WriteByte(b *strings.Builder, c byte) {
	if b == nil {
		return
	}
	b.WriteByte(c)
}

func Fuzz_Builder_WriteRune(b *strings.Builder, r rune) {
	if b == nil {
		return
	}
	b.WriteRune(r)
}

func Fuzz_Builder_WriteString(b *strings.Builder, s string) {
	if b == nil {
		return
	}
	b.WriteString(s)
}

func Fuzz_Reader_Len(s string) {
	r := strings.NewReader(s)
	r.Len()
}

func Fuzz_Reader_Read(s string, b []byte) {
	r := strings.NewReader(s)
	r.Read(b)
}

func Fuzz_Reader_ReadAt(s string, b []byte, off int64) {
	r := strings.NewReader(s)
	r.ReadAt(b, off)
}

func Fuzz_Reader_ReadByte(s string) {
	r := strings.NewReader(s)
	r.ReadByte()
}

func Fuzz_Reader_ReadRune(s string) {
	r := strings.NewReader(s)
	r.ReadRune()
}

func Fuzz_Reader_Reset(s1 string, s2 string) {
	r := strings.NewReader(s1)
	r.Reset(s2)
}

func Fuzz_Reader_Seek(s string, offset int64, whence int) {
	r := strings.NewReader(s)
	r.Seek(offset, whence)
}

func Fuzz_Reader_Size(s string) {
	r := strings.NewReader(s)
	r.Size()
}

func Fuzz_Reader_UnreadByte(s string) {
	r := strings.NewReader(s)
	r.UnreadByte()
}

func Fuzz_Reader_UnreadRune(s string) {
	r := strings.NewReader(s)
	r.UnreadRune()
}

func Fuzz_Reader_WriteTo(s string, w io.Writer) {
	r := strings.NewReader(s)
	r.WriteTo(w)
}

func Fuzz_Replacer_Replace(oldnew []string, s string) {
	r := strings.NewReplacer(oldnew...)
	r.Replace(s)
}

func Fuzz_Replacer_WriteString(oldnew []string, w io.Writer, s string) {
	r := strings.NewReplacer(oldnew...)
	r.WriteString(w, s)
}

func Fuzz_Compare(a string, b string) {
	strings.Compare(a, b)
}

func Fuzz_Contains(s string, substr string) {
	strings.Contains(s, substr)
}

func Fuzz_ContainsAny(s string, chars string) {
	strings.ContainsAny(s, chars)
}

func Fuzz_ContainsRune(s string, r rune) {
	strings.ContainsRune(s, r)
}

func Fuzz_Count(s string, substr string) {
	strings.Count(s, substr)
}

func Fuzz_EqualFold(s string, t string) {
	strings.EqualFold(s, t)
}

func Fuzz_Fields(s string) {
	strings.Fields(s)
}

// skipping Fuzz_FieldsFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_HasPrefix(s string, prefix string) {
	strings.HasPrefix(s, prefix)
}

func Fuzz_HasSuffix(s string, suffix string) {
	strings.HasSuffix(s, suffix)
}

func Fuzz_Index(s string, substr string) {
	strings.Index(s, substr)
}

func Fuzz_IndexAny(s string, chars string) {
	strings.IndexAny(s, chars)
}

func Fuzz_IndexByte(s string, c byte) {
	strings.IndexByte(s, c)
}

// skipping Fuzz_IndexFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_IndexRune(s string, r rune) {
	strings.IndexRune(s, r)
}

func Fuzz_Join(elems []string, sep string) {
	strings.Join(elems, sep)
}

func Fuzz_LastIndex(s string, substr string) {
	strings.LastIndex(s, substr)
}

func Fuzz_LastIndexAny(s string, chars string) {
	strings.LastIndexAny(s, chars)
}

func Fuzz_LastIndexByte(s string, c byte) {
	strings.LastIndexByte(s, c)
}

// skipping Fuzz_LastIndexFunc because parameters include interfaces or funcs: func(rune) bool

// skipping Fuzz_Map because parameters include interfaces or funcs: func(rune) rune

func Fuzz_NewReader(s string) {
	strings.NewReader(s)
}

func Fuzz_NewReplacer(oldnew []string) {
	strings.NewReplacer(oldnew...)
}

func Fuzz_Repeat(s string, count int) {
	strings.Repeat(s, count)
}

func Fuzz_Replace(s string, old string, new string, n int) {
	strings.Replace(s, old, new, n)
}

func Fuzz_ReplaceAll(s string, old string, new string) {
	strings.ReplaceAll(s, old, new)
}

func Fuzz_Split(s string, sep string) {
	strings.Split(s, sep)
}

func Fuzz_SplitAfter(s string, sep string) {
	strings.SplitAfter(s, sep)
}

func Fuzz_SplitAfterN(s string, sep string, n int) {
	strings.SplitAfterN(s, sep, n)
}

func Fuzz_SplitN(s string, sep string, n int) {
	strings.SplitN(s, sep, n)
}

func Fuzz_Title(s string) {
	strings.Title(s)
}

func Fuzz_ToLower(s string) {
	strings.ToLower(s)
}

func Fuzz_ToLowerSpecial(c unicode.SpecialCase, s string) {
	strings.ToLowerSpecial(c, s)
}

func Fuzz_ToTitle(s string) {
	strings.ToTitle(s)
}

func Fuzz_ToTitleSpecial(c unicode.SpecialCase, s string) {
	strings.ToTitleSpecial(c, s)
}

func Fuzz_ToUpper(s string) {
	strings.ToUpper(s)
}

func Fuzz_ToUpperSpecial(c unicode.SpecialCase, s string) {
	strings.ToUpperSpecial(c, s)
}

func Fuzz_ToValidUTF8(s string, replacement string) {
	strings.ToValidUTF8(s, replacement)
}

func Fuzz_Trim(s string, cutset string) {
	strings.Trim(s, cutset)
}

// skipping Fuzz_TrimFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_TrimLeft(s string, cutset string) {
	strings.TrimLeft(s, cutset)
}

// skipping Fuzz_TrimLeftFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_TrimPrefix(s string, prefix string) {
	strings.TrimPrefix(s, prefix)
}

func Fuzz_TrimRight(s string, cutset string) {
	strings.TrimRight(s, cutset)
}

// skipping Fuzz_TrimRightFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_TrimSpace(s string) {
	strings.TrimSpace(s)
}

func Fuzz_TrimSuffix(s string, suffix string) {
	strings.TrimSuffix(s, suffix)
}
`},
		{
			name:               "strings: exported only, local pkg",
			onlyExported:       true,
			qualifyAll:         false,
			insertConstructors: true,
			want: `package strings

// if needed, fill in imports or run 'goimports'
import (
	"io"
	"unicode"
)

func Fuzz_Builder_Cap(b *Builder) {
	if b == nil {
		return
	}
	b.Cap()
}

func Fuzz_Builder_Grow(b *Builder, n int) {
	if b == nil {
		return
	}
	b.Grow(n)
}

func Fuzz_Builder_Len(b *Builder) {
	if b == nil {
		return
	}
	b.Len()
}

func Fuzz_Builder_Reset(b *Builder) {
	if b == nil {
		return
	}
	b.Reset()
}

func Fuzz_Builder_String(b *Builder) {
	if b == nil {
		return
	}
	b.String()
}

func Fuzz_Builder_Write(b *Builder, p []byte) {
	if b == nil {
		return
	}
	b.Write(p)
}

func Fuzz_Builder_WriteByte(b *Builder, c byte) {
	if b == nil {
		return
	}
	b.WriteByte(c)
}

func Fuzz_Builder_WriteRune(b *Builder, r rune) {
	if b == nil {
		return
	}
	b.WriteRune(r)
}

func Fuzz_Builder_WriteString(b *Builder, s string) {
	if b == nil {
		return
	}
	b.WriteString(s)
}

func Fuzz_Reader_Len(s string) {
	r := NewReader(s)
	r.Len()
}

func Fuzz_Reader_Read(s string, b []byte) {
	r := NewReader(s)
	r.Read(b)
}

func Fuzz_Reader_ReadAt(s string, b []byte, off int64) {
	r := NewReader(s)
	r.ReadAt(b, off)
}

func Fuzz_Reader_ReadByte(s string) {
	r := NewReader(s)
	r.ReadByte()
}

func Fuzz_Reader_ReadRune(s string) {
	r := NewReader(s)
	r.ReadRune()
}

func Fuzz_Reader_Reset(s1 string, s2 string) {
	r := NewReader(s1)
	r.Reset(s2)
}

func Fuzz_Reader_Seek(s string, offset int64, whence int) {
	r := NewReader(s)
	r.Seek(offset, whence)
}

func Fuzz_Reader_Size(s string) {
	r := NewReader(s)
	r.Size()
}

func Fuzz_Reader_UnreadByte(s string) {
	r := NewReader(s)
	r.UnreadByte()
}

func Fuzz_Reader_UnreadRune(s string) {
	r := NewReader(s)
	r.UnreadRune()
}

func Fuzz_Reader_WriteTo(s string, w io.Writer) {
	r := NewReader(s)
	r.WriteTo(w)
}

func Fuzz_Replacer_Replace(oldnew []string, s string) {
	r := NewReplacer(oldnew...)
	r.Replace(s)
}

func Fuzz_Replacer_WriteString(oldnew []string, w io.Writer, s string) {
	r := NewReplacer(oldnew...)
	r.WriteString(w, s)
}

func Fuzz_Compare(a string, b string) {
	Compare(a, b)
}

func Fuzz_Contains(s string, substr string) {
	Contains(s, substr)
}

func Fuzz_ContainsAny(s string, chars string) {
	ContainsAny(s, chars)
}

func Fuzz_ContainsRune(s string, r rune) {
	ContainsRune(s, r)
}

func Fuzz_Count(s string, substr string) {
	Count(s, substr)
}

func Fuzz_EqualFold(s string, t string) {
	EqualFold(s, t)
}

func Fuzz_Fields(s string) {
	Fields(s)
}

// skipping Fuzz_FieldsFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_HasPrefix(s string, prefix string) {
	HasPrefix(s, prefix)
}

func Fuzz_HasSuffix(s string, suffix string) {
	HasSuffix(s, suffix)
}

func Fuzz_Index(s string, substr string) {
	Index(s, substr)
}

func Fuzz_IndexAny(s string, chars string) {
	IndexAny(s, chars)
}

func Fuzz_IndexByte(s string, c byte) {
	IndexByte(s, c)
}

// skipping Fuzz_IndexFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_IndexRune(s string, r rune) {
	IndexRune(s, r)
}

func Fuzz_Join(elems []string, sep string) {
	Join(elems, sep)
}

func Fuzz_LastIndex(s string, substr string) {
	LastIndex(s, substr)
}

func Fuzz_LastIndexAny(s string, chars string) {
	LastIndexAny(s, chars)
}

func Fuzz_LastIndexByte(s string, c byte) {
	LastIndexByte(s, c)
}

// skipping Fuzz_LastIndexFunc because parameters include interfaces or funcs: func(rune) bool

// skipping Fuzz_Map because parameters include interfaces or funcs: func(rune) rune

func Fuzz_NewReader(s string) {
	NewReader(s)
}

func Fuzz_NewReplacer(oldnew []string) {
	NewReplacer(oldnew...)
}

func Fuzz_Repeat(s string, count int) {
	Repeat(s, count)
}

func Fuzz_Replace(s string, old string, new string, n int) {
	Replace(s, old, new, n)
}

func Fuzz_ReplaceAll(s string, old string, new string) {
	ReplaceAll(s, old, new)
}

func Fuzz_Split(s string, sep string) {
	Split(s, sep)
}

func Fuzz_SplitAfter(s string, sep string) {
	SplitAfter(s, sep)
}

func Fuzz_SplitAfterN(s string, sep string, n int) {
	SplitAfterN(s, sep, n)
}

func Fuzz_SplitN(s string, sep string, n int) {
	SplitN(s, sep, n)
}

func Fuzz_Title(s string) {
	Title(s)
}

func Fuzz_ToLower(s string) {
	ToLower(s)
}

func Fuzz_ToLowerSpecial(c unicode.SpecialCase, s string) {
	ToLowerSpecial(c, s)
}

func Fuzz_ToTitle(s string) {
	ToTitle(s)
}

func Fuzz_ToTitleSpecial(c unicode.SpecialCase, s string) {
	ToTitleSpecial(c, s)
}

func Fuzz_ToUpper(s string) {
	ToUpper(s)
}

func Fuzz_ToUpperSpecial(c unicode.SpecialCase, s string) {
	ToUpperSpecial(c, s)
}

func Fuzz_ToValidUTF8(s string, replacement string) {
	ToValidUTF8(s, replacement)
}

func Fuzz_Trim(s string, cutset string) {
	Trim(s, cutset)
}

// skipping Fuzz_TrimFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_TrimLeft(s string, cutset string) {
	TrimLeft(s, cutset)
}

// skipping Fuzz_TrimLeftFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_TrimPrefix(s string, prefix string) {
	TrimPrefix(s, prefix)
}

func Fuzz_TrimRight(s string, cutset string) {
	TrimRight(s, cutset)
}

// skipping Fuzz_TrimRightFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_TrimSpace(s string) {
	TrimSpace(s)
}

func Fuzz_TrimSuffix(s string, suffix string) {
	TrimSuffix(s, suffix)
}
`},
		{
			name:               "strings: exported only, not local pkg, no constructors",
			onlyExported:       true,
			qualifyAll:         true,
			insertConstructors: false,
			want: `package stringsfuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import (
	"io"
	"strings"
	"unicode"
)

func Fuzz_Builder_Cap(b *strings.Builder) {
	if b == nil {
		return
	}
	b.Cap()
}

func Fuzz_Builder_Grow(b *strings.Builder, n int) {
	if b == nil {
		return
	}
	b.Grow(n)
}

func Fuzz_Builder_Len(b *strings.Builder) {
	if b == nil {
		return
	}
	b.Len()
}

func Fuzz_Builder_Reset(b *strings.Builder) {
	if b == nil {
		return
	}
	b.Reset()
}

func Fuzz_Builder_String(b *strings.Builder) {
	if b == nil {
		return
	}
	b.String()
}

func Fuzz_Builder_Write(b *strings.Builder, p []byte) {
	if b == nil {
		return
	}
	b.Write(p)
}

func Fuzz_Builder_WriteByte(b *strings.Builder, c byte) {
	if b == nil {
		return
	}
	b.WriteByte(c)
}

func Fuzz_Builder_WriteRune(b *strings.Builder, r rune) {
	if b == nil {
		return
	}
	b.WriteRune(r)
}

func Fuzz_Builder_WriteString(b *strings.Builder, s string) {
	if b == nil {
		return
	}
	b.WriteString(s)
}

func Fuzz_Reader_Len(r *strings.Reader) {
	if r == nil {
		return
	}
	r.Len()
}

func Fuzz_Reader_Read(r *strings.Reader, b []byte) {
	if r == nil {
		return
	}
	r.Read(b)
}

func Fuzz_Reader_ReadAt(r *strings.Reader, b []byte, off int64) {
	if r == nil {
		return
	}
	r.ReadAt(b, off)
}

func Fuzz_Reader_ReadByte(r *strings.Reader) {
	if r == nil {
		return
	}
	r.ReadByte()
}

func Fuzz_Reader_ReadRune(r *strings.Reader) {
	if r == nil {
		return
	}
	r.ReadRune()
}

func Fuzz_Reader_Reset(r *strings.Reader, s string) {
	if r == nil {
		return
	}
	r.Reset(s)
}

func Fuzz_Reader_Seek(r *strings.Reader, offset int64, whence int) {
	if r == nil {
		return
	}
	r.Seek(offset, whence)
}

func Fuzz_Reader_Size(r *strings.Reader) {
	if r == nil {
		return
	}
	r.Size()
}

func Fuzz_Reader_UnreadByte(r *strings.Reader) {
	if r == nil {
		return
	}
	r.UnreadByte()
}

func Fuzz_Reader_UnreadRune(r *strings.Reader) {
	if r == nil {
		return
	}
	r.UnreadRune()
}

func Fuzz_Reader_WriteTo(r *strings.Reader, w io.Writer) {
	if r == nil {
		return
	}
	r.WriteTo(w)
}

func Fuzz_Replacer_Replace(r *strings.Replacer, s string) {
	if r == nil {
		return
	}
	r.Replace(s)
}

func Fuzz_Replacer_WriteString(r *strings.Replacer, w io.Writer, s string) {
	if r == nil {
		return
	}
	r.WriteString(w, s)
}

func Fuzz_Compare(a string, b string) {
	strings.Compare(a, b)
}

func Fuzz_Contains(s string, substr string) {
	strings.Contains(s, substr)
}

func Fuzz_ContainsAny(s string, chars string) {
	strings.ContainsAny(s, chars)
}

func Fuzz_ContainsRune(s string, r rune) {
	strings.ContainsRune(s, r)
}

func Fuzz_Count(s string, substr string) {
	strings.Count(s, substr)
}

func Fuzz_EqualFold(s string, t string) {
	strings.EqualFold(s, t)
}

func Fuzz_Fields(s string) {
	strings.Fields(s)
}

// skipping Fuzz_FieldsFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_HasPrefix(s string, prefix string) {
	strings.HasPrefix(s, prefix)
}

func Fuzz_HasSuffix(s string, suffix string) {
	strings.HasSuffix(s, suffix)
}

func Fuzz_Index(s string, substr string) {
	strings.Index(s, substr)
}

func Fuzz_IndexAny(s string, chars string) {
	strings.IndexAny(s, chars)
}

func Fuzz_IndexByte(s string, c byte) {
	strings.IndexByte(s, c)
}

// skipping Fuzz_IndexFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_IndexRune(s string, r rune) {
	strings.IndexRune(s, r)
}

func Fuzz_Join(elems []string, sep string) {
	strings.Join(elems, sep)
}

func Fuzz_LastIndex(s string, substr string) {
	strings.LastIndex(s, substr)
}

func Fuzz_LastIndexAny(s string, chars string) {
	strings.LastIndexAny(s, chars)
}

func Fuzz_LastIndexByte(s string, c byte) {
	strings.LastIndexByte(s, c)
}

// skipping Fuzz_LastIndexFunc because parameters include interfaces or funcs: func(rune) bool

// skipping Fuzz_Map because parameters include interfaces or funcs: func(rune) rune

func Fuzz_NewReader(s string) {
	strings.NewReader(s)
}

func Fuzz_NewReplacer(oldnew []string) {
	strings.NewReplacer(oldnew...)
}

func Fuzz_Repeat(s string, count int) {
	strings.Repeat(s, count)
}

func Fuzz_Replace(s string, old string, new string, n int) {
	strings.Replace(s, old, new, n)
}

func Fuzz_ReplaceAll(s string, old string, new string) {
	strings.ReplaceAll(s, old, new)
}

func Fuzz_Split(s string, sep string) {
	strings.Split(s, sep)
}

func Fuzz_SplitAfter(s string, sep string) {
	strings.SplitAfter(s, sep)
}

func Fuzz_SplitAfterN(s string, sep string, n int) {
	strings.SplitAfterN(s, sep, n)
}

func Fuzz_SplitN(s string, sep string, n int) {
	strings.SplitN(s, sep, n)
}

func Fuzz_Title(s string) {
	strings.Title(s)
}

func Fuzz_ToLower(s string) {
	strings.ToLower(s)
}

func Fuzz_ToLowerSpecial(c unicode.SpecialCase, s string) {
	strings.ToLowerSpecial(c, s)
}

func Fuzz_ToTitle(s string) {
	strings.ToTitle(s)
}

func Fuzz_ToTitleSpecial(c unicode.SpecialCase, s string) {
	strings.ToTitleSpecial(c, s)
}

func Fuzz_ToUpper(s string) {
	strings.ToUpper(s)
}

func Fuzz_ToUpperSpecial(c unicode.SpecialCase, s string) {
	strings.ToUpperSpecial(c, s)
}

func Fuzz_ToValidUTF8(s string, replacement string) {
	strings.ToValidUTF8(s, replacement)
}

func Fuzz_Trim(s string, cutset string) {
	strings.Trim(s, cutset)
}

// skipping Fuzz_TrimFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_TrimLeft(s string, cutset string) {
	strings.TrimLeft(s, cutset)
}

// skipping Fuzz_TrimLeftFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_TrimPrefix(s string, prefix string) {
	strings.TrimPrefix(s, prefix)
}

func Fuzz_TrimRight(s string, cutset string) {
	strings.TrimRight(s, cutset)
}

// skipping Fuzz_TrimRightFunc because parameters include interfaces or funcs: func(rune) bool

func Fuzz_TrimSpace(s string) {
	strings.TrimSpace(s)
}

func Fuzz_TrimSuffix(s string, suffix string) {
	strings.TrimSuffix(s, suffix)
}
`},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgPattern := "strings"
			options := flagExcludeFuzzPrefix | flagAllowMultiFuzz
			if tt.onlyExported {
				options |= flagRequireExported
			}
			functions, err := FindFunc(pkgPattern, ".", nil, options)
			if err != nil {
				t.Errorf("FindFuncfail() failed: %v", err)
			}

			wrapperOpts := wrapperOptions{
				qualifyAll:         tt.qualifyAll,
				insertConstructors: tt.insertConstructors,
				constructorPattern: "^New",
			}
			out, err := createWrappers(pkgPattern, functions, wrapperOpts)
			if err != nil {
				t.Errorf("createWrappers() failed: %v", err)
			}

			got := string(out)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("createWrappers() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
