module example

// This is a separate module because it relies on go 1.18,
// such as *testing.F for native cmd/go fuzzing.

go 1.18

replace (
	github.com/thepudds/fzgen => ./../..
	github.com/thepudds/fzgen/examples/inputs/race-xsync-map => ./../../examples/inputs/race-xsync-map
	github.com/thepudds/fzgen/examples/inputs/race-xsync-mpmcqueue => ./../../examples/inputs/race-xsync-mpmcqueue
)

require (
	github.com/google/uuid v1.3.0
	github.com/thepudds/fzgen v0.0.0-00010101000000-000000000000
	github.com/thepudds/fzgen/examples/inputs/race-xsync-map v0.0.0-00010101000000-000000000000
	github.com/thepudds/fzgen/examples/inputs/race-xsync-mpmcqueue v0.0.0-00010101000000-000000000000
	golang.zx2c4.com/go118/netip v0.0.0-20211111135330-a4a02eeacf9d
	inet.af/netaddr v0.0.0-20211027220019-c74959edd3b6
)

require (
	github.com/RoaringBitmap/roaring v0.9.4 // indirect
	github.com/bits-and-blooms/bitset v1.2.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/mschoch/smat v0.2.0 // indirect
	github.com/puzpuzpuz/xsync v1.0.1-0.20210823092703-32778049b5f5 // indirect
	github.com/sanity-io/litter v1.5.1 // indirect
	go4.org/intern v0.0.0-20211027215823-ae77deb06f29 // indirect
	go4.org/unsafe/assume-no-moving-gc v0.0.0-20211027215541-db492cf91b37 // indirect
)
