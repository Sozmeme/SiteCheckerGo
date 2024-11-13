package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

type CheckRequest struct {
	URL string `json:"url"`
}

type CheckResponse struct {
	ReportText string `json:"report_text"`
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	var req CheckRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	checker := NewMasterChecker()
	report := checker.Check(req.URL)

	resp := CheckResponse{ReportText: report.Text}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func main() {
	http.HandleFunc("/check", checkHandler)

	port := "8080"
	fmt.Printf("Server is running on port %s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Could not start server: %s\n", err)
	}
}
