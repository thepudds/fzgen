module example

// This is a separate module because it relies on go 1.18,
// such as *testing.F for native cmd/go fuzzing.

go 1.18

replace (
	github.com/thepudds/fzgen => ./../..
	github.com/thepudds/fzgen/examples/inputs/race-xsync-map => ./../../examples/inputs/race-xsync-map
)

require (
	github.com/RoaringBitmap/roaring v0.9.4
	github.com/google/uuid v1.3.0
	github.com/thepudds/fzgen v0.0.0-00010101000000-000000000000
	github.com/thepudds/fzgen/examples/inputs/race-xsync-map v0.0.0-00010101000000-000000000000
)

require (
	github.com/bits-and-blooms/bitset v1.2.0 // indirect
	github.com/mschoch/smat v0.2.0 // indirect
	github.com/puzpuzpuz/xsync v1.0.1-0.20210823092703-32778049b5f5 // indirect
	github.com/sanity-io/litter v1.5.1 // indirect
)
