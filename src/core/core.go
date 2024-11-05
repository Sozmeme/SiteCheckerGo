package core

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Report struct {
	Text   string
	Metric float64
}

type Checker interface {
	check(url string) Report
}

type MasterChecker struct {
	judges []Checker
}

func (ma *MasterChecker) Check(checkURL string) Report {
	report := Report{Text: "", Metric: 1.0}

	parsedURL, err := url.Parse(checkURL)
	if err != nil {
		report.Text = fmt.Sprintf("Invalid URL: %v", err)
		report.Metric = 0
		return report
	}
	hostname := strings.TrimPrefix(parsedURL.Hostname(), "www.")

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(checkURL)
	if err != nil {
		report.Text = fmt.Sprintf("Error connecting to URL: %v", err)
		report.Metric = 0
		return report
	}
	defer resp.Body.Close()

	if len(resp.Request.URL.String()) > 0 && resp.Request.URL.String() != checkURL {
		newURL := resp.Request.URL.String()
		newHostname := strings.TrimPrefix(resp.Request.URL.Hostname(), "www.")
		report.Text += fmt.Sprintf("[!] URL %q redirects to %q\n", checkURL, newURL)
		checkURL = newURL
		if newHostname != hostname {
			report.Metric *= 0.4
		}
	}

	totalMetric := report.Metric
	for _, judge := range ma.judges {
		judgeReport := judge.check(checkURL)
		totalMetric += judgeReport.Metric
		report.Text += fmt.Sprintf("[+] Result from %T:\n%s", judge, judgeReport.Text)
	}

	report.Metric = round(totalMetric / float64(len(ma.judges)+1))
	report.Text += fmt.Sprintf("[!] Final trust score: %.2f - ", report.Metric)
	if report.Metric >= 0.7 {
		report.Text += "The site is safe to visit"
	} else {
		report.Text += "The site may be malicious"
	}
	return report
}

func round(value float64) float64 {
	return float64(int(value*100)) / 100
}