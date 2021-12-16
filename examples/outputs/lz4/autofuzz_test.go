package lz4fuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import (
	"io"
	"testing"

	"github.com/pierrec/lz4/v4"
	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_Compressor_CompressBlock(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var c *lz4.Compressor
		var src []byte
		var dst []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&c, &src, &dst)
		if c == nil {
			return
		}

		c.CompressBlock(src, dst)
	})
}

func Fuzz_CompressorHC_CompressBlock(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var c *lz4.CompressorHC
		var src []byte
		var dst []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&c, &src, &dst)
		if c == nil {
			return
		}

		c.CompressBlock(src, dst)
	})
}

// skipping Fuzz_Reader_Apply because parameters include unsupported func or chan: []github.com/pierrec/lz4/v4.Option

func Fuzz_Reader_Read(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r io.Reader
		var buf []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r, &buf)

		r1 := lz4.NewReader(r)
		r1.Read(buf)
	})
}

func Fuzz_Reader_Reset(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r io.Reader
		var reader io.Reader
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r, &reader)

		r1 := lz4.NewReader(r)
		r1.Reset(reader)
	})
}

func Fuzz_Reader_Size(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r io.Reader
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r)

		r1 := lz4.NewReader(r)
		r1.Size()
	})
}

func Fuzz_Reader_WriteTo(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r io.Reader
		var w io.Writer
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r, &w)

		r1 := lz4.NewReader(r)
		r1.WriteTo(w)
	})
}

// skipping Fuzz_Writer_Apply because parameters include unsupported func or chan: []github.com/pierrec/lz4/v4.Option

func Fuzz_Writer_Close(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var w io.Writer
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&w)

		w1 := lz4.NewWriter(w)
		w1.Close()
	})
}

func Fuzz_Writer_ReadFrom(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var w io.Writer
		var r io.Reader
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&w, &r)

		w1 := lz4.NewWriter(w)
		w1.ReadFrom(r)
	})
}

func Fuzz_Writer_Reset(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var w io.Writer
		var writer io.Writer
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&w, &writer)

		w1 := lz4.NewWriter(w)
		w1.Reset(writer)
	})
}

func Fuzz_Writer_Write(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var w io.Writer
		var buf []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&w, &buf)

		w1 := lz4.NewWriter(w)
		w1.Write(buf)
	})
}

func Fuzz_BlockSize_String(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var i lz4.BlockSize
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&i)

		i.String()
	})
}

func Fuzz_CompressionLevel_String(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var i lz4.CompressionLevel
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&i)

		i.String()
	})
}

// skipping Fuzz_Option_String because parameters include unsupported func or chan: github.com/pierrec/lz4/v4.Option

func Fuzz_BlockChecksumOption(f *testing.F) {
	f.Fuzz(func(t *testing.T, flag bool) {
		lz4.BlockChecksumOption(flag)
	})
}

func Fuzz_BlockSizeOption(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var size lz4.BlockSize
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&size)

		lz4.BlockSizeOption(size)
	})
}

func Fuzz_ChecksumOption(f *testing.F) {
	f.Fuzz(func(t *testing.T, flag bool) {
		lz4.ChecksumOption(flag)
	})
}

func Fuzz_CompressBlock(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var src []byte
		var dst []byte
		var _x3 []int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&src, &dst, &_x3)

		lz4.CompressBlock(src, dst, _x3)
	})
}

func Fuzz_CompressBlockBound(f *testing.F) {
	f.Fuzz(func(t *testing.T, n int) {
		lz4.CompressBlockBound(n)
	})
}

func Fuzz_CompressBlockHC(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var src []byte
		var dst []byte
		var depth lz4.CompressionLevel
		var _x4 []int
		var _x5 []int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&src, &dst, &depth, &_x4, &_x5)

		lz4.CompressBlockHC(src, dst, depth, _x4, _x5)
	})
}

func Fuzz_CompressionLevelOption(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var level lz4.CompressionLevel
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&level)

		lz4.CompressionLevelOption(level)
	})
}

func Fuzz_ConcurrencyOption(f *testing.F) {
	f.Fuzz(func(t *testing.T, n int) {
		lz4.ConcurrencyOption(n)
	})
}

func Fuzz_LegacyOption(f *testing.F) {
	f.Fuzz(func(t *testing.T, legacy bool) {
		lz4.LegacyOption(legacy)
	})
}

func Fuzz_NewReader(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r io.Reader
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r)

		lz4.NewReader(r)
	})
}

func Fuzz_NewWriter(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var w io.Writer
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&w)

		lz4.NewWriter(w)
	})
}

// skipping Fuzz_OnBlockDoneOption because parameters include unsupported func or chan: func(size int)

func Fuzz_SizeOption(f *testing.F) {
	f.Fuzz(func(t *testing.T, size uint64) {
		lz4.SizeOption(size)
	})
}

func Fuzz_UncompressBlock(f *testing.F) {
	f.Fuzz(func(t *testing.T, src []byte, dst []byte) {
		lz4.UncompressBlock(src, dst)
	})
}

func Fuzz_UncompressBlockWithDict(f *testing.F) {
	f.Fuzz(func(t *testing.T, src []byte, dst []byte, dict []byte) {
		lz4.UncompressBlockWithDict(src, dst, dict)
	})
}

func Fuzz_ValidFrameHeader(f *testing.F) {
	f.Fuzz(func(t *testing.T, in []byte) {
		lz4.ValidFrameHeader(in)
	})
}
