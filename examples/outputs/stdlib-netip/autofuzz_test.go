package netipfuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import (
	"testing"

	"github.com/thepudds/fzgen/fuzzer"
	"golang.zx2c4.com/go118/netip"
)

func Fuzz_Addr_UnmarshalBinary(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip *netip.Addr
		var b []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip, &b)
		if ip == nil {
			return
		}

		ip.UnmarshalBinary(b)
	})
}

func Fuzz_Addr_UnmarshalText(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip *netip.Addr
		var text []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip, &text)
		if ip == nil {
			return
		}

		ip.UnmarshalText(text)
	})
}

func Fuzz_AddrPort_UnmarshalBinary(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p *netip.AddrPort
		var b []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p, &b)
		if p == nil {
			return
		}

		p.UnmarshalBinary(b)
	})
}

func Fuzz_AddrPort_UnmarshalText(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p *netip.AddrPort
		var text []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p, &text)
		if p == nil {
			return
		}

		p.UnmarshalText(text)
	})
}

func Fuzz_Prefix_UnmarshalBinary(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p *netip.Prefix
		var b []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p, &b)
		if p == nil {
			return
		}

		p.UnmarshalBinary(b)
	})
}

func Fuzz_Prefix_UnmarshalText(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p *netip.Prefix
		var text []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p, &text)
		if p == nil {
			return
		}

		p.UnmarshalText(text)
	})
}

func Fuzz_Addr_AppendTo(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		var b []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip, &b)

		ip.AppendTo(b)
	})
}

func Fuzz_Addr_As16(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.As16()
	})
}

func Fuzz_Addr_As4(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.As4()
	})
}

func Fuzz_Addr_AsSlice(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.AsSlice()
	})
}

func Fuzz_Addr_BitLen(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.BitLen()
	})
}

func Fuzz_Addr_Compare(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		var ip2 netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip, &ip2)

		ip.Compare(ip2)
	})
}

func Fuzz_Addr_Is4(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.Is4()
	})
}

func Fuzz_Addr_Is4In6(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.Is4In6()
	})
}

func Fuzz_Addr_Is6(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.Is6()
	})
}

func Fuzz_Addr_IsGlobalUnicast(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.IsGlobalUnicast()
	})
}

func Fuzz_Addr_IsInterfaceLocalMulticast(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.IsInterfaceLocalMulticast()
	})
}

func Fuzz_Addr_IsLinkLocalMulticast(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.IsLinkLocalMulticast()
	})
}

func Fuzz_Addr_IsLinkLocalUnicast(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.IsLinkLocalUnicast()
	})
}

func Fuzz_Addr_IsLoopback(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.IsLoopback()
	})
}

func Fuzz_Addr_IsMulticast(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.IsMulticast()
	})
}

func Fuzz_Addr_IsPrivate(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.IsPrivate()
	})
}

func Fuzz_Addr_IsUnspecified(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.IsUnspecified()
	})
}

func Fuzz_Addr_IsValid(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.IsValid()
	})
}

func Fuzz_Addr_Less(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		var ip2 netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip, &ip2)

		ip.Less(ip2)
	})
}

func Fuzz_Addr_MarshalBinary(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.MarshalBinary()
	})
}

func Fuzz_Addr_MarshalText(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.MarshalText()
	})
}

func Fuzz_Addr_Next(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.Next()
	})
}

func Fuzz_Addr_Prefix(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		var b int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip, &b)

		ip.Prefix(b)
	})
}

func Fuzz_Addr_Prev(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.Prev()
	})
}

func Fuzz_Addr_String(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.String()
	})
}

func Fuzz_Addr_StringExpanded(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.StringExpanded()
	})
}

func Fuzz_Addr_Unmap(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.Unmap()
	})
}

func Fuzz_Addr_WithZone(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		var zone string
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip, &zone)

		ip.WithZone(zone)
	})
}

func Fuzz_Addr_Zone(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip)

		ip.Zone()
	})
}

func Fuzz_AddrPort_Addr(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.AddrPort
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p)

		p.Addr()
	})
}

func Fuzz_AddrPort_AppendTo(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.AddrPort
		var b []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p, &b)

		p.AppendTo(b)
	})
}

func Fuzz_AddrPort_IsValid(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.AddrPort
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p)

		p.IsValid()
	})
}

func Fuzz_AddrPort_MarshalBinary(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.AddrPort
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p)

		p.MarshalBinary()
	})
}

func Fuzz_AddrPort_MarshalText(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.AddrPort
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p)

		p.MarshalText()
	})
}

func Fuzz_AddrPort_Port(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.AddrPort
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p)

		p.Port()
	})
}

func Fuzz_AddrPort_String(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.AddrPort
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p)

		p.String()
	})
}

func Fuzz_Prefix_Addr(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.Prefix
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p)

		p.Addr()
	})
}

func Fuzz_Prefix_AppendTo(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.Prefix
		var b []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p, &b)

		p.AppendTo(b)
	})
}

func Fuzz_Prefix_Bits(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.Prefix
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p)

		p.Bits()
	})
}

func Fuzz_Prefix_Contains(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.Prefix
		var ip netip.Addr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p, &ip)

		p.Contains(ip)
	})
}

func Fuzz_Prefix_IsSingleIP(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.Prefix
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p)

		p.IsSingleIP()
	})
}

func Fuzz_Prefix_IsValid(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.Prefix
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p)

		p.IsValid()
	})
}

func Fuzz_Prefix_MarshalBinary(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.Prefix
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p)

		p.MarshalBinary()
	})
}

func Fuzz_Prefix_MarshalText(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.Prefix
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p)

		p.MarshalText()
	})
}

func Fuzz_Prefix_Masked(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.Prefix
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p)

		p.Masked()
	})
}

func Fuzz_Prefix_Overlaps(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.Prefix
		var o netip.Prefix
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p, &o)

		p.Overlaps(o)
	})
}

func Fuzz_Prefix_String(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p netip.Prefix
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&p)

		p.String()
	})
}

func Fuzz_AddrFrom16(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var addr [16]byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&addr)

		netip.AddrFrom16(addr)
	})
}

func Fuzz_AddrFrom4(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var addr [4]byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&addr)

		netip.AddrFrom4(addr)
	})
}

func Fuzz_AddrFromSlice(f *testing.F) {
	f.Fuzz(func(t *testing.T, slice []byte) {
		netip.AddrFromSlice(slice)
	})
}

func Fuzz_AddrPortFrom(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		var port uint16
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip, &port)

		netip.AddrPortFrom(ip, port)
	})
}

func Fuzz_MustParseAddr(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		netip.MustParseAddr(s)
	})
}

func Fuzz_MustParseAddrPort(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		netip.MustParseAddrPort(s)
	})
}

func Fuzz_MustParsePrefix(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		netip.MustParsePrefix(s)
	})
}

func Fuzz_ParseAddr(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		netip.ParseAddr(s)
	})
}

func Fuzz_ParseAddrPort(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		netip.ParseAddrPort(s)
	})
}

func Fuzz_ParsePrefix(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		netip.ParsePrefix(s)
	})
}

func Fuzz_PrefixFrom(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ip netip.Addr
		var bits int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ip, &bits)

		netip.PrefixFrom(ip, bits)
	})
}
