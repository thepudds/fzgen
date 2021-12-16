## genfuzzfuncs: generate fuzz functions from user code 

`genfuzzfuncs` is an early stage prototype for automatically generating fuzz functions, similar in spirit to [cweill/gotests](https://github.com/cweill/gotests). It is not intended to be part of the "first class fuzzing" proposal for cmd/go.

For example, if you run genfuzzfuncs against github.com/google/uuid, it generates a [uuid_fuzz.go](https://github.com/thepudds/fzgo/blob/master/genfuzzfuncs/examples/uuid/uuid_fuzz.go) file with 30 or so functions like:

```
func Fuzz_UUID_MarshalText(u1 uuid.UUID) {
    u1.MarshalText()
}

func Fuzz_UUID_UnmarshalText(u1 *uuid.UUID, data []byte) {
    if u1 == nil {
	    return
    }
    u1.UnmarshalText(data)
}
```

You can then edit or delete as desired, and then fuzz using the rich signature fuzzing support in thepudds/fzgo, such as:

```
fzgo test -fuzz=. ./...
```
