package fzgen

import (
	"flag"
	"log"
	"os"
	"runtime"
	"testing"

	"github.com/rogpeppe/go-internal/gotooltest"
	"github.com/rogpeppe/go-internal/testscript"
	gen "github.com/thepudds/fzgen/gen"
)

var end2EndFlag = flag.Bool("end2end", false, "run longer end-to-end tests that assume a 1.18 gotip in PATH")

func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(fzgenTestingMain{m}, map[string]func() int{
		"fzgen": gen.FzgenMain,
	}))
}

func TestScripts(t *testing.T) {
	if !*end2EndFlag {
		t.Skip("skipping longer end-to-end tests that assume a 1.18 gotip in PATH. use -end2end flag to run.")
	}
	p := testscript.Params{
		Dir: "testscripts",
		// For gotip from our path to work without re-downloading,
		// we need a valid HOME env var. Testscripts default to HOME=/no-home
		// If we don't do this here, get failure:
		//     gotip: not downloaded. Run 'gotip download' to install to /no-home/sdk/gotip
		Setup: func(e *testscript.Env) error {
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatal(err)
			}
			wd, err := os.Getwd()
			if err != nil {
				log.Fatal(err)
			}
			e.Vars = append(e.Vars,
				homeEnvVar()+"="+home,
				"FZLOCALDIR="+wd,
			)
			return nil
		},
		// TestWork: true, // setting -testwork should work, so hopefully no need to manually set here
	}
	if err := gotooltest.Setup(&p); err != nil {
		t.Fatal(err)
	}
	testscript.Run(t, p)
}

type fzgenTestingMain struct {
	m *testing.M
}

func (m fzgenTestingMain) Run() int {
	// could do additional setup here if needed (e.g., check or set env vars, start a Go proxy server, etc.)
	return m.m.Run()
}

func homeEnvVar() string {
	if runtime.GOOS == "windows" {
		return "USERPROFILE"
	}
	return "HOME"
}
