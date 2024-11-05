package sslcheck

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
	"sitechecker/src/core"
)

type SSLchecker struct {
}

func (sc SSLchecker) Check(checkURL string) core.Report {
	report := core.Report{Text: "", Metric: 1}
	u, err := url.Parse(checkURL)

	if err != nil {
		log.Fatal(err)
	}

	hostname := u.Host
	conn, err := tls.Dial("tcp", hostname+":443", nil)
	if err != nil {
		report.Text += err.Error() + "\n"
		report.Metric = 0
		return report
	}

	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	issuedTo := cert.Subject
	issuedBy := cert.Issuer
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter

	// Проверка на организацию
	if len(issuedTo.Organization) == 0 {
		report.Text += fmt.Sprintf(
			`- SSL сертификат подтверждает только домен: "%s"
- Кем выдан: "%s"
- Срок действия сертификата: "%s" - "%s"`,
			issuedTo.CommonName, issuedBy.Organization[0],
			notBefore.Format("2006-01-02"), notAfter.Format("2006-01-02")) + "\n"
		report.Metric = 0.5
	} else {
		report.Text += fmt.Sprintf(
			`- Сертификат выдан домену: "%s"
- Для организации: "%s"
- Кем выдан: "%s"
- Срок действия сертификата: "%s" - "%s"`,
			issuedTo.CommonName, issuedTo.Organization[0], issuedBy.Organization[0],
			notBefore.Format("2006-01-02"), notAfter.Format("2006-01-02")) + "\n"
		report.Metric = 1
	}

	return report
}
