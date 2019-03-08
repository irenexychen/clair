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
	cesaURL = "https://cefs.b-cdn.net/errata.latest.xml"
	cveURL  = "https://access.redhat.com/labs/securitydataapi/cve.json"

	updaterFlag = "centosUpdater"
	//affectedType = database.BinaryPackage
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

	r_cesa, err := httputil.GetWithUserAgent(cesaURL)
	if err != nil {
		log.WithError(err).Error("could not download CESA's errata update")
		return resp, commonerr.ErrCouldNotDownload
	}
	defer r_cesa.Body.Close()
	if !httputil.Status2xx(r_cesa) {
		log.WithField("StatusCode", r_cesa.StatusCode).Error("Failed to update CentOS CESA db")
		return resp, commonerr.ErrCouldNotDownload
	}
	data, err := ioutil.ReadAll(r_cesa.Body)
	if err != nil {
		log.WithError(err).Error("could not read CESA body")
		return resp, commonerr.ErrCouldNotParse
	}

	vs, err := parseCESA(string(data))
	if err != nil {
		return resp, err
	}
	for _, v := range vs {
		resp.Vulnerabilities = append(resp.Vulnerabilities, v)
	}

	r_cve, err := httputil.GetWithUserAgent(cveURL)
	if err != nil {
		log.WithError(err).Error("could not download CVEs from RH API update")
		return resp, commonerr.ErrCouldNotDownload
	}
	defer r_cve.Body.Close()
	if !httputil.Status2xx(r_cve) {
		log.WithField("StatusCode", r_cesa.StatusCode).Error("Failed to update CentOS CVE db from API")
		return resp, commonerr.ErrCouldNotDownload
	}
	data, err = ioutil.ReadAll(r_cve.Body)
	if err != nil {
		log.WithError(err).Error("could not read CVE body")
		return resp, commonerr.ErrCouldNotParse
	}

	vs, err = parseCVE(string(data))
	if err != nil {
		return resp, err
	}
	for _, v := range vs {
		resp.Vulnerabilities = append(resp.Vulnerabilities, v)
	}

	return resp, nil
}

func parseCESA(cesaData string) (vulnerabilities []database.Vulnerability, err error) {
	// func parseCESA(cesaReader io.Reader) (vulnerabilities []database.Vulnerability, err error) {
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

			vuln.Name = sa.XMLName.Local
			vuln.Link = sa.References
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
	return
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

			var vuln database.Vulnerability
			vuln.Name = c.Name
			vuln.Link = c.Bugzilla.URL
			vuln.Description = c.Bugzilla.Description
			vuln.Severity = convertSeverity(c.ThreatSeverity)

			for _, pack := range c.PackageState {
				var versionP string
				//err = versionfmt.Valid(rpm.ParserName, pack.FixState)
				//if err != nil {
				//	log.WithError(err).WithField("version", pack.FixState).Warning("could not parse package version. skipping")
				//} else {
				switch strings.ToLower(strings.TrimSpace(pack.FixState)) {
				case "new", "affected", "will not fix":
					versionP = versionfmt.MaxVersion
				case "not affected":
					versionP = versionfmt.MinVersion
				default:
					versionP = strings.TrimSpace(pack.FixState)
				}

				featureVersion := database.FeatureVersion{
					Feature: database.Feature{
						Namespace: database.Namespace{
							Name:          "centos:" + pack.ProductName[len(pack.ProductName)-1:],
							VersionFormat: rpm.ParserName,
						},
						Name: strings.TrimSpace(pack.PackageName),
					},
					Version: versionP,
				}
				vuln.FixedIn = append(vuln.FixedIn, featureVersion)
			}
			vulnerabilities = append(vulnerabilities, vuln)
		} else {
			log.WithError(err).Error("could not download " + cve.CVEName + " from RH API update, skipping")
			// return resp, commonerr.ErrCouldNotDownload
			// SKIP THIS CVE
		}
	}
	return
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
