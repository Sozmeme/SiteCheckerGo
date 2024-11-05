package main

import (
	"sitechecker/src/urlcheck"
	"fmt"
)

func main() {
	checker := urlcheck.URLchecker{}
	report := checker.Check("https://itmo.ru")
	fmt.Print(report.Text)
	

}