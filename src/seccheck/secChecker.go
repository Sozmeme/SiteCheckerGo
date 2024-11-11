package seccheck

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"sitechecker/src/core"
)

type SecChecker struct{}

func (p SecChecker) Check(url string) core.Report {
	report := core.Report{
		Text:   "",
		Metric: 1.0,
	}

	// Выполняем HTTP-запрос
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println(err.Error())
	}
	req.Header.Set("User-Agent", "some good user-agent")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err.Error())
	}
	defer resp.Body.Close()

	// Читаем содержимое ответа
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err.Error())
	}

	// Преобразуем тело в строку
	html := string(body)

	// Ищем небезопасные функции
	unsafeFunctions := []string{"eval", "Function", "setInterval"}
	for _, funcName := range unsafeFunctions {
		regex := regexp.MustCompile(fmt.Sprintf(`\b%s\s*\(`, regexp.QuoteMeta(funcName)))
		if regex.FindString(html) != "" {
			report.Text += fmt.Sprintf("- Обнаружен вызов %s() - возможно внедрение вредоносного кода\n", funcName)
			report.Metric *= 0.6
		}
	}

	// Проверка необходимых заголовков
	requiredHeaders := map[string]float64{
		"Content-Security-Policy":   0.7,
		"X-XSS-Protection":          0.8,
		"Strict-Transport-Security": 0.7,
		"X-Frame-Options":           0.8,
	}
	for header, factor := range requiredHeaders {
		if resp.Header.Get(header) == "" {
			report.Text += fmt.Sprintf("- Отсутствует заголовок %s\n", header)
			report.Metric *= factor
		}
	}

	return report
}
