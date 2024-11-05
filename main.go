package main

import (
	"sitechecker/src/seccheck"
	"fmt"
)

func main() {
	checker := seccheck.SecChecker{}
	report := checker.Check("https://itmo.ru")
	fmt.Print(report.Text)
	

}