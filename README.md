go run ./main.go
curl -X POST http://localhost:8080/check -H "Content-Type: application/json" -d "{\"url\": \"https://google.com\"}"
