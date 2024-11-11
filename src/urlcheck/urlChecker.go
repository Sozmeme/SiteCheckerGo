package urlcheck

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sitechecker/src/core"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/xrash/smetrics"
)

type URLchecker struct {
}

func (uc URLchecker) Check(checkURL string) core.Report {
	report := core.Report{Text: "", Metric: 1}
	hostname := getHostname(checkURL)
	siteName := getSiteName(hostname)
	createdAt, err := getCreationDate(hostname)
	pageRank, rankerr := getPageRank(hostname)
	

	// Проверка даты создания сайта
	if err != nil || createdAt.IsZero() {
		if pageRank < 4 {
			report.Text += fmt.Sprintf("- Не удалось получить информацию о дате создания сайта \"%s\" - возможно, он создан недавно\n", hostname)
			report.Metric *= 0.3
		}
	} else {
		text, metric := analyzeCreationDate(createdAt)
		report.Text += text
		report.Metric *= metric
	}

	// Проверка PageRank
	if rankerr != nil {
		report.Text += "- PageRank не доступен\n"
	} else {
		if pageRank < 4 {
			report.Text += fmt.Sprintf("- Низкий PageRank по данным CommonCrawl - \"%d/10\"\n", pageRank)
			report.Metric *= 0.3
		} else {
			report.Text += fmt.Sprintf("- PageRank по данным CommonCrawl - \"%d/10\"\n", pageRank)
		}
	}

	// Проверка на количество поддоменов
	if strings.Count(hostname, ".") > 2 {
		report.Text += "- Большое количество поддоменов\n"
		report.Metric *= 0.5
	}

	// Проверка на дефис
	if strings.Contains(hostname, "-") {
		report.Text += "- Содержит дефис в имени хоста\n"
		report.Metric *= 0.7
	}

	// Проверка на подмену алфавита и цифры
	if msg := checkAlphabetSubstitution(hostname); msg != "OK" {
		report.Text += msg
		report.Metric *= 0.5
	}
	if msg := checkDigit(hostname); msg != "OK" {
		report.Text += msg
		report.Metric *= 0.7
	}

	// Проверка на доверенные домены
	trustedDomains := loadTrustedDomains("src/white list.txt")
	for _, trustedDomain := range trustedDomains {
		if similar := isSimilarDomain(siteName, trustedDomain); similar != "OK" {
			report.Text += fmt.Sprintf("- Найдена схожесть с доверенным доменом: %s\n", trustedDomain)
			report.Metric *= 0.4
			break
		}
	}

	return report
}

func getHostname(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func getSiteName(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) > 1 {
		return parts[len(parts)-2]
	}
	return ""
}

func getCreationDate(hostname string) (time.Time, error) {
	result, err := whois.Whois(hostname)
	if err != nil {
		return time.Time{}, err
	}
	parsedResult, err := whoisparser.Parse(result)
	if err != nil {
		return time.Time{}, err
	}
	return *parsedResult.Domain.CreatedDateInTime, nil
}

type Config struct {
	APIKey string `json:"api_key"`
}

func loadConfig() (*Config, error) {
	file, err := os.Open("config.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	return &config, err
}

type Response struct {
	Response []struct {
		PageRankInteger int `json:"page_rank_integer"`
	} `json:"response"`
}

func getPageRank(hostname string) (int, error) {
	config, err := loadConfig()
	if err != nil {
		fmt.Println("Error loading config:", err)
		return 0, err
	}

	url := fmt.Sprintf("https://openpagerank.com/api/v1.0/getPageRank?domains%%5B0%%5D=%s", hostname)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("API-OPR", config.APIKey)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result Response
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	if len(result.Response) > 0 {
		return result.Response[0].PageRankInteger, nil
	}

	return 0, fmt.Errorf("pagerank is not available")

}

func analyzeCreationDate(createdAt time.Time) (string, float64) {
	curDate := time.Now()
	if createdAt.AddDate(0, 6, 0).After(curDate) {
		return fmt.Sprintf("- Сайт создан не более 6 месяцев назад: %v\n", createdAt), 0.4
	} else if createdAt.AddDate(1, 0, 0).After(curDate) {
		return fmt.Sprintf("- Сайт создан не более года назад: %v\n", createdAt), 1
	} else if createdAt.AddDate(5, 0, 0).Before(curDate) {
		return fmt.Sprintf("- Сайт создан более 5 лет назад: %v\n", createdAt), 1
	}
	return fmt.Sprintf("- Сайт создан более года назад: %v\n", createdAt), 1
}

func checkAlphabetSubstitution(hostname string) string {
	alphSub := map[rune]string{'е': "e", 'о': "o", 'с': "c", 'р': "p", 'а': "a", '0': "o", '@': "a", 'ь': "b"}
	var msg string
	for _, char := range hostname {
		if sub, ok := alphSub[char]; ok {
			msg += fmt.Sprintf("- возможна подмена: %s\n", sub)
		}
	}
	if msg == "" {
		return "OK"
	}
	return msg
}

func checkDigit(hostname string) string {
	for _, char := range hostname {
		if char >= '0' && char <= '9' {
			return fmt.Sprintf("- %s содержит цифры\n", hostname)
		}
	}
	return "OK"
}

func loadTrustedDomains(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Ошибка открытия файла: %v\n", err)
		return nil
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domains = append(domains, strings.TrimSpace(scanner.Text()))
	}
	return domains
}

func isSimilarDomain(siteName, trustedDomain string) string {
	similarity := smetrics.JaroWinkler(siteName, trustedDomain, 0.7, 4)
	if similarity >= 0.9 {
		return "Similar"
	}
	return "OK"
}
