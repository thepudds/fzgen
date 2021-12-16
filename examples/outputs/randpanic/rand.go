package myrand

import "math/rand"

func PanicRandomly1000(a int) {
	if rand.Int31n(1000) == 0 {
		panic("1 in a 1000")
	}
}

func PanicRandomly10000(a int) {
	if rand.Int31n(10000) == 0 {
		panic("1 in a 10000")
	}
}

func PanicRandomly100000(a int) {
	if rand.Int31n(100000) == 0 {
		panic("1 in a 100000")
	}
}

func PanicOn10(a int) {
	if a == 10 {
		panic("sent 10")
	}
}

func PanicOn10000(a int) {
	if a == 10000 {
		panic("sent 10000")
	}
}

