# SiteChecker
This app checks site via URL and gives a report about safey usage of this site.

It analyzes:
- SSL certificate
- Whois information
- Pagerank
- URL lexical features
- HTTP safety headers
- Usage of unsafe functions like eval()

Evaluation of final trustscore is based on my personal experimental data.
# Usage
```terminal
go run ./main.go
curl -X POST http://localhost:8080/check -H "Content-Type: application/json" -d "{\"url\": \"https://google.com\"}"
