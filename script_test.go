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

var (
	end2EndFlag     = flag.Bool("end2end", false, "run longer end-to-end tests that assume a 1.18 gotip in PATH")
	updateFlag      = flag.Bool("update", false, "update the second argument of any failing cmp commands in a testscript")
	allExternalFlag = flag.Bool("allexternal", false, "run all external package tests (currently only supported with bash and assumes git)")
)

func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(fzgenTestingMain{m}, map[string]func() int{
		"fzgen": gen.FzgenMain,
	}))
}

func TestScripts(t *testing.T) {
	if !*end2EndFlag {
		// TODO: probably push this check into the individual testscripts by using Params.Condition?
		t.Skip("skipping longer end-to-end tests that assume a 1.18 gotip in PATH. use -end2end flag to run.")
	}
	p := testscript.Params{
		Dir:           "testscripts",
		UpdateScripts: *updateFlag,
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
		Condition: func(cond string) (bool, error) {
			switch cond {
			case "end2end":
				return *end2EndFlag, nil
			case "allexternal":
				return *allExternalFlag, nil
			}
			return false, nil
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
