// Copyright 2019
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package centos implements a vulnerability source updater using the
// RedHat security data api, cross-checked with the CESA list from Centos Announce

// TODO: correlate CESA information with RH, see centos_cve_scanner.py

package centos

import (
	"encoding/json"
	"encoding/xml"
	"io/ioutil"
	"regexp"

	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/httputil"
)

const (
	cesaURL       = "https://cefs.b-cdn.net/errata.latest.xml"
	baseURL       = "https://access.redhat.com/labs/securitydataapi/cve/"
	cveURL        = "https://access.redhat.com/labs/securitydataapi/cve.json"
	conversionURL = "https://www.redhat.com/security/data/metrics/rhsamapcpe.txt"
	updaterFlag   = "centosUpdater"
)

type updater struct{}

func init() {
	vulnsrc.RegisterUpdater("centos", &updater{})
	log.WithField("package", "CentOS").Info("initialized")
}

func (u *updater) Clean() {}

type CESA struct {
	XMLName xml.Name `xml:"opt"`
	SA      []struct {
		XMLName     xml.Name
		Description string   `xml:"description,attr"`
		From        string   `xml:"from,attr"`
		IssueDate   string   `xml:"issue_date,attr"`
		Notes       string   `xml:"notes,attr"`
		Product     string   `xml:"product,attr"`
		References  string   `xml:"references,attr"`
		Release     string   `xml:"release,attr"`
		Severity    string   `xml:"severity,attr"`
		Solution    string   `xml:"solution,attr"`
		Synopsis    string   `xml:"synopsis,attr"`
		Topic       string   `xml:"topic,attr"`
		Type        string   `xml:"type,attr"`
		OsArch      string   `xml:"os_arch"`
		OsRelease   string   `xml:"os_release"`
		Packages    []string `xml:"packages"`
	} `xml:",any"`
}

type CVES []struct {
	CVEName             string    `json:"CVE"`
	Severity            string    `json:"severity"`
	Date                time.Time `json:"public_date"`
	Advisories          []string  `json:"advisories"`
	Bugzilla            string    `json:"bugzilla"`
	BugzillaDescription string    `json:"bugzilla_description"`
	CWE                 string    `json:"CWE"`
	AffectedPackages    []string  `json:"affected_packages"`
	ResourceURL         string    `json:"resource_url"`
	Cvss3Score          float64   `json:"cvss3_score"`
}

type CVE struct {
	ThreatSeverity string `json:"threat_severity"`
	PublicDate     string `json:"public_date"`
	Bugzilla       struct {
		Description string `json:"description"`
		ID          string `json:"id"`
		URL         string `json:"url"`
	} `json:"bugzilla"`
	Cvss3 struct {
		Cvss3BaseScore     string `json:"cvss3_base_score"`
		Cvss3ScoringVector string `json:"cvss3_scoring_vector"`
		Status             string `json:"status"`
	} `json:"cvss3"`
	Cwe          string   `json:"cwe"`
	Details      []string `json:"details"`
	PackageState []struct {
		ProductName string `json:"product_name"`
		FixState    string `json:"fix_state"`
		PackageName string `json:"package_name"`
		Cpe         string `json:"cpe"`
	} `json:"package_state"`
	Name string `json:"name"`
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "CentOS").Info("start fetching vulnerabilities")

	_, err = datastore.GetKeyValue(updaterFlag)
	if err != nil {
		return resp, err
	}
	// rConv, err := httputil.GetWithUserAgent(conversionURL)
	// if err != nil {
	// 	log.WithError(err).Error("Could not get RHSA to CVE conversion")
	// 	return resp, commonerr.ErrCouldNotDownload
	// }
	// defer rConv.Body.Close()
	// if !httputil.Status2xx(rConv) {
	// 	log.WithField("StatusCode", rConv.StatusCode).Error("Failed to download RHSA to CVE conversion db")
	// 	return resp, commonerr.ErrCouldNotDownload
	// }
	// data, err := ioutil.ReadAll(rConv.Body)
	// if err != nil {
	// 	log.WithError(err).Error("could not read RHSA to CVE conversion response")
	// 	return resp, commonerr.ErrCouldNotParse
	// }
	// rhsaToCve := parseConv(string(data))

	// rCesa, err := httputil.GetWithUserAgent(cesaURL)
	// if err != nil {
	// 	log.WithError(err).Error("could not download CESA's errata update")
	// 	return resp, commonerr.ErrCouldNotDownload
	// }
	// defer rCesa.Body.Close()
	// if !httputil.Status2xx(rCesa) {
	// 	log.WithField("StatusCode", rCesa.StatusCode).Error("Failed to update CentOS CESA db")
	// 	return resp, commonerr.ErrCouldNotDownload
	// }
	// data, err = ioutil.ReadAll(rCesa.Body)
	// if err != nil {
	// 	log.WithError(err).Error("could not read CESA body")
	// 	return resp, commonerr.ErrCouldNotParse
	// }
	// listFromCesa, err := parseCESA(string(data), rhsaToCve)
	// if err != nil {
	// 	return resp, err
	// }
	// log.WithField("package", "CentOS").Info("finished fetching CESA list of vulnerabilities")

	rCve, err := httputil.GetWithUserAgent(cveURL)
	if err != nil {
		log.WithError(err).Error("could not download CVEs from RH API update")
		return resp, commonerr.ErrCouldNotDownload
	}
	defer rCve.Body.Close()
	if !httputil.Status2xx(rCve) {
		log.WithField("StatusCode", rCve.StatusCode).Error("Failed to update CentOS CVE db from API")
		return resp, commonerr.ErrCouldNotDownload
	}
	data, err := ioutil.ReadAll(rCve.Body)
	if err != nil {
		log.WithError(err).Error("could not read CVE body")
		return resp, commonerr.ErrCouldNotParse
	}
	vsCve, errCve := parseCVE(string(data))
	// vsCve, errCve := parseCVE(string(data), listFromCesa)
	if errCve != nil {
		return resp, errCve
	}
	for _, v := range vsCve {
		resp.Vulnerabilities = append(resp.Vulnerabilities, v)
	}
	log.WithField("package", "CentOS").Info("finished populating CVE vulnerabilities")

	return resp, nil
}

func parseCESA(cesaData string) (vulnerabilities []database.Vulnerability, err error) {
	log.WithField("package", "CentOS").Info("Parsing CESA xml")

	var cesas CESA

	err = xml.Unmarshal([]byte(cesaData), &cesas)

	if err != nil {
		log.WithError(err).Error("could not decode CESA's XML")
		return vulnerabilities, commonerr.ErrCouldNotParse
	}
	log.WithField("package", "CentOS").Info("Decoded CESA XML")

	for _, sa := range cesas.SA {
		if strings.Contains(sa.XMLName.Local, "CESA") && len(sa.Packages) > 0 {
			var vuln database.Vulnerability
			url := strings.Split(sa.References, " ")

			vuln.Name = sa.XMLName.Local
			vuln.Link = url[0]
			vuln.Description = sa.Description
			vuln.Severity = convertSeverity(sa.Severity)

			for _, pack := range sa.Packages {
				err = versionfmt.Valid(rpm.ParserName, strings.TrimSpace(pack))
				if err != nil {
					log.WithError(err).WithField("version", pack).Warning("could not parse package version. skipping")
				} else {
					featureVersion := database.FeatureVersion{
						Feature: database.Feature{
							Namespace: database.Namespace{
								Name:          "centos:" + sa.OsRelease,
								VersionFormat: rpm.ParserName,
							},
							Name: strings.TrimSpace(pack),
						},
						Version: strings.TrimSpace(pack),
					}
					vuln.FixedIn = append(vuln.FixedIn, featureVersion)
				}
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}
	log.WithField("package", "CentOS").Info("finished parsing CESA vulnerabilities")

	return vulnerabilities, nil
}

func parseCVE(cveData string) (vulnerabilities []database.Vulnerability, err error) {
	log.WithField("package", "CentOS").Info("Parsing CVES json")

	var cves CVES
	err = json.Unmarshal([]byte(cveData), &cves)

	if err != nil {
		log.WithError(err).Error("could not decode CVES json")
		return vulnerabilities, commonerr.ErrCouldNotParse
	}
	log.WithField("package", "CentOS").Info("Decoded CVES json")

	for _, cve := range cves {
		r, err := httputil.GetWithUserAgent(strings.TrimSpace(cve.ResourceURL))
		defer r.Body.Close()
		data, err := ioutil.ReadAll(r.Body)

		if err == nil || httputil.Status2xx(r) {
			var c CVE
			json.Unmarshal([]byte(data), &c)
			url := strings.Split(c.Bugzilla.URL, " ")

			var vuln database.Vulnerability
			vuln.Name = c.Name
			vuln.Link = url[0]
			vuln.Description = c.Bugzilla.Description
			vuln.Severity = convertSeverity(c.ThreatSeverity)

			for _, pack := range c.PackageState {
				// var versionP string
				// switch strings.ToLower(strings.TrimSpace(pack.FixState)) {
				// case "new", "affected", "will not fix":
				// 	versionP = versionfmt.MaxVersion
				// case "not affected":
				// 	versionP = versionfmt.MinVersion
				// default:
				// 	versionP = strings.TrimSpace(pack.FixState)
				// }

				rhelPlatform, _ := regexp.Match(`red hat enterprise linux .`, []byte(strings.ToLower(pack.ProductName)))
				if (!packs[nameP]) && rhelPlatform && (strings.ToLower(pack.FixState) != "not affected") {
					featureVersion := database.FeatureVersion{
						Feature: database.Feature{
							Namespace: database.Namespace{
								Name:          "centos:" + pack.ProductName[len(pack.ProductName)-1:],
								VersionFormat: rpm.ParserName,
							},
							Name: strings.TrimSpace(pack.PackageName),
						},
						Version: versionfmt.MaxVersion,
					}
					vuln.FixedIn = append(vuln.FixedIn, featureVersion)
				}
			}
			if len(vuln.FixedIn) > 0 { //assert CVE has relevant packages
				vulnerabilities = append(vulnerabilities, vuln)
			}
		} else {
			log.WithError(err).Error("could not download " + cve.CVEName + " from RH API update, skipping")
			// return resp, commonerr.ErrCouldNotDownload
			// SKIP THIS CVE
		}
	}
	log.WithField("package", "CentOS").Info("finished parsing CVE vulnerabilities")

	return vulnerabilities, nil
}

func convertSeverity(sev string) database.Severity {
	switch strings.ToLower(sev) {
	case "none", "n/a":
		return database.NegligibleSeverity
	case "low":
		return database.LowSeverity
	case "moderate":
		return database.MediumSeverity
	case "important", "high":
		return database.HighSeverity
	case "critical":
		return database.CriticalSeverity
	default:
		log.WithField("severity", sev).Warning("could not determine vulnerability severity")
		return database.UnknownSeverity
	}
}
