package main

import (
	"fmt"
	"sitechecker/src/core"
	"sitechecker/src/seccheck"
	"sitechecker/src/sslcheck"
	"sitechecker/src/urlcheck"
)

func NewMasterChecker() core.Checker {
	return &core.MasterChecker{
		Judges: []core.Checker{
			sslcheck.SSLchecker{},
			urlcheck.URLchecker{},
			seccheck.SecChecker{},
		},
	}
}

func main() {
	checker := NewMasterChecker()
	report := checker.Check("https://google.com")
	fmt.Print(report.Text)
}
