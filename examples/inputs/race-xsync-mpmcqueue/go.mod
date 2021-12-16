module github.com/thepudds/fzgen/examples/inputs/race-xsyncmap

go 1.17

require (
	github.com/puzpuzpuz/xsync v1.0.1-0.20210823092703-32778049b5f5
	github.com/thepudds/fzgen v0.0.0-00010101000000-000000000000
)

require (
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/sanity-io/litter v1.5.1 // indirect
)

replace github.com/thepudds/fzgen => ./../../..
