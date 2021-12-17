# fzgen

fzgen auto-generates fuzzing wrappers for Go 1.18, optionally finds problematic API call sequences, can automatically wire outputs to inputs across API calls, and supports rich types such as structs, maps, slices, named types, and common interfaces.

## Why?

Fewer bugs, happy Gophers.

Modern fuzzing has had a large amount of [success](https://events.linuxfoundation.org/wp-content/uploads/2017/11/Syzbot-and-the-Tale-of-Thousand-Kernel-Bugs-Dmitry-Vyukov-Google.pdf) and can be almost [eerily smart](https://lcamtuf.blogspot.com/2014/11/pulling-jpegs-out-of-thin-air.html), but has been most heavily used in the realm of security, often with a focus on [parsing untrusted inputs](https://google.github.io/oss-fuzz/faq/#what-kind-of-projects-are-you-accepting).

Security is critical, but:

 1. Eventually, the bigger success for fuzzing might be **finding correctness & stability problems** in a broader set of code bases, and beyond today's more common security focus.
 2. There is also a large opportunity to **make fuzzing easier to pick up** by a broader community.

This project aims to pitch in on those two fronts.

If enough people work to make the fuzzing ecosystem accessible enough, "coffee break fuzzing" might eventually become as common as unit tests. And of course, increased adoption of fuzzing helps security as well. :blush:

## Quick Start: Install & Automatically Create Fuzz Targets

Starting from an empty directory, create a module and install the dev version of Go 1.18 via gotip:
```
$ go mod init example
$ go install golang.org/dl/gotip@latest
$ gotip download
```

Download and install the fzgen binary from source, as well as add its fuzzer to our go.mod:
```
$ go install github.com/thepudds/fzgen/cmd/fzgen@latest
$ go get github.com/thepudds/fzgen/fuzzer
```

Use fzgen to automatically create a set of fuzz targets -- in this case for the encoding/ascii85 package from the Go standard library:
```
$ fzgen encoding/ascii85
fzgen: created autofuzz_test.go
```

That's it -- now we can start fuzzing!
```
$ gotip test -fuzz=Fuzz_Encode
```

Within a few seconds, you should get a crash:
```
[...]
fuzz: minimizing 56-byte failing input file
fuzz: elapsed: 0s, minimizing
--- FAIL: Fuzz_Encode (0.06s)
```

Without any manual work, you just found a bug in the standard library. (It's a very minor bug though -- probably at the level of "perhaps the doc could be more explicit about an expected panic").

That's enough for you to get started on your own, but let's also briefly look at a more interesting example.

## Example: Easily Finding a Data Race

Again starting from an empty directory, we'll set up a module, and add the fzgen fuzzer to go.mod:
```
$ go mod init temp
$ go get github.com/thepudds/fzgen/fuzzer
```

Next, we automatically create a new fuzz target. This time:
 * We ask fzgen to "chain" a set of methods together in a calling sequence controlled by fzgen.Fuzzer (via the `-chain` argument).
 * We also tell fzgen that it should in theory be safe to do parallel execution of those methods across multiple goroutines (via the `-parallel` argument).

```
$ fzgen -chain -parallel github.com/thepudds/fzgen/examples/inputs/race
fzgen: created autofuzzchain_test.go
```

That's it! Let's get fuzzing. 

This time, we also enable the race detector as we fuzz:
```
$ gotip test -fuzz=. -race
```

This is a harder challenge than our first example, but within several minutes or so, you should get a data race detected:
```
--- FAIL: Fuzz_NewMySafeMap (4.26s)
    --- FAIL: Fuzz_NewMySafeMap (0.01s)
        testing.go:1282: race detected during execution of test
```
 
If we want to see what exact calls triggered this, along with their input arguments, we can set a fzgen debug flag asking it to show us a reproducer, and then ask 'go test' to re-run the failing input that was just found. (Your failing example will almost certainly have a different filename and show a different pattern of calls).

```
$ export FZDEBUG=repro=1                   # On Windows:  set FZDEBUG=repro=1
$ gotip test -run=./9800b52 -race
```

This will output a snippet of valid Go code that represents the reproducer:
```go
        // PLANNED STEPS (loop count: 1, spin: true)

        Fuzz_MySafeMap_Store(
                [16]uint8{152,152,152,152,152,152,152,152,152,152,152,152,152,152,152,152},
                &raceexample.Request{Answer:42,},
        )

        var wg sync.WaitGroup
        wg.Add(2)

        // Execute next steps in parallel.
        go func() {
                defer wg.Done()
                Fuzz_MySafeMap_Load(
                        [16]uint8{152,152,152,152,152,152,152,152,152,152,152,152,152,152,152,152},
                )
        }()
        go func() {
                defer wg.Done()
                Fuzz_MySafeMap_Load(
                        [16]uint8{152,152,152,152,152,152,152,152,152,152,152,152,152,152,152,152},
                )
        }()
        wg.Wait()

        // Resume sequential execution.
        Fuzz_MySafeMap_Load(
                [16]uint8{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
        )

[...]
    --- FAIL: Fuzz_NewMySafeMap (0.01s)
        testing.go:1282: race detected during execution of test
```

Note that just running a regular test under the race detector might not catch this bug, including because the race detector [only finds data races that happen at runtime](https://go.dev/blog/race-detector), which means a diversity of code paths and input data is imporant for the race detector to do its job.
fz.Chain helps supply those code paths and data -- in this case, usually hundreds of thousands of coverage-guided variations before hitting the data race.

For this particular [bug](https://github.com/thepudds/fzgen/blob/master/examples/inputs/race/race.go#L34-L36) to be observable by the race detector, it requires:

  1. A Store must complete, then be followed by two Loads, and all three must use the same key.
  2. The Store must have certain payload data (`Answer: 42`).
  3. The two Loads must happen concurrently.
  4. Prior to the two Loads, no other Store can update the key to have a non-matching payload.

Here, the `42` seen in the reproducer must be `42`. On the other hand, the exact value of `152,152,152,...` in the key doesn't matter, but what does matter is that the same key value must be used across this sequence of three calls to trigger the bug. 

fz.Chain has logic to sometimes re-use input arguments of the same type across different calls (e.g., to make it easier to have a meaningful `Get(key)` following a `Put(key)`), as well logic to feed outputs of one step as the input to a subsequent step, which is helpful in other cases.

Rewinding slightly, if you look at the code you just automatically generated in [autofuzzchain_test.go](https://github.com/thepudds/fzgen/blob/main/examples/outputs/race/autofuzzchain_test.go), you can see there are a set of possible "steps" listed that each invoke the target, but the most important line there is:

```go
    // Execute a specific chain of steps, with the count, sequence and arguments controlled by fz.Chain
    fz.Chain(steps, fuzzer.ChainParallel)
```

In other words, at execution time, fz.Chain takes over and guides the underlying fuzzing engine towards interesting calling patterns & arguments, while simultaneously exploring what runs in parallel vs. sequentially, the timing of parallel calls, and so on.

## Example: Finding a Real Concurrency Bug in Real Code

The prior example was a small but challenging example that takes a few minutes of fuzzing to find, but you can see an example of a deadlock found in real code [here](https://github.com/thepudds/fzgen/blob/master/examples/outputs/race-xsync-map-repro/standalone_repro1_test.go) from the xsync.Map from github.com/puzpuzpuz/xsync.

In this case, it usually takes fz.Chain several million coverage-guided variations over a few hours of executing the generated 
 [autogenchain_test.go](https://github.com/thepudds/fzgen/blob/master/examples/outputs/race-xsync-map/autofuzzchain_test.go) before it finds the deadlock.

Interestingly, the deadlock then typically only reproduces about 1 out of 1,000 attempts for a particular discovered problematic calling pattern and arguments.

Fortunately, once a problem is reported, we can paste the output of `FZDEBUG=repro=1` into a [standalone_repro_test.go](https://github.com/thepudds/fzgen/blob/master/examples/outputs/race-xsync-map-repro/standalone_repro1_test.go) file and use the handy `-count` argument in a normal `go test -count=10000` invocation, and now we can reproduce the deadlock cleanly on demand. At that point, the reproducer is completely standalone and does not rely on fzgen any longer.

## fzgen status

* fzgen is still a work in progress, but hopefully will soon be approaching beta quality. 
* Emitting reproducers for a chain is currently best effort, but the intent is to improve to creating a complete standalone reproducer.
* Corpus encoding in particular will change in the near term.
* Roughly by the time of Go 1.18 graduates from Beta, the current intent is that fzgen will reach a 1.0 status.
    * By 1.0, fzgen will have a stable corpus encoding, or an equivalent (such as perhaps the ability to programmatically set an encoding version number to keep using a corpus that is an older fzgen encoding).

## What next?

Any and all feedback is welcome! :grinning:

Please feel free to open a new issue here, or to contact the author on Twitter ([@thepudds1](https://twitter.com/thepudds1)).

The roadmap issue (TODO) in particular is a reasonable starting place. 

If you made it this far -- thanks!
