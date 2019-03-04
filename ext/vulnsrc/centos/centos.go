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
	"encoding/xml"
	// "encoding/json"

	// "fmt"
	"io"

	//"regexp"
	//"strconv"
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
	cveURLPrefix = "https://access.redhat.com/labs/securitydataapi/"
	cveURL       = "https://access.redhat.com/labs/securitydataapi/cve.json"
	ovalURL      = "https://access.redhat.com/labs/securitydataapi/oval.json"
	cesaURL      = "http://cefs.steve-meier.de/errata.latest.xml"
	updaterFlag  = "centosUpdater"

	//affectedType = database.BinaryPackage
)

type updater struct{}

func init() {
	vulnsrc.RegisterUpdater("centos", &updater{})
	log.WithField("package", "CentOS").Info("initialized")
}

func (u *updater) Clean() {}

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

type OVAL []struct {
	RHSA        string    `json:"RHSA"`
	Severity    string    `json:"severity"`
	Date        time.Time `json:"released_on"`
	CVEs        []string  `json:"CVEs"`
	Bugzillas   []string  `json:"bugzillas"`
	ResourceURL string    `json:"resource_url"`
}

type CESA struct {
	XMLName xml.Name `xml:"opt"`
	SA      []struct {
		Text        string   `xml:",chardata"`
		Description string   `xml:"description,attr"`
		From        string   `xml:"from,attr"`
		IssueDate   string   `xml:"issue_date,attr"`
		Notes       string   `xml:"notes,attr"`
		Product     string   `xml:"product,attr"`
		References  string   `xml:"references,attr"`
		Release     string   `xml:"release,attr"`
		Solution    string   `xml:"solution,attr"`
		Synopsis    string   `xml:"synopsis,attr"`
		Topic       string   `xml:"topic,attr"`
		Type        string   `xml:"type,attr"`
		OsRelease   string   `xml:"os_release"`
		Packages    []string `xml:"packages"`
	} `xml:",any"`
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "CentOS").Info("start fetching vulnerabilities")
	// flagValue, err := datastore.GetKeyValue(updaterFlag)
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
	resp, err = buildResponse(r_cesa.Body)

	//    r_cve, err := httputil.GetWithUserAgent(cveURL)
	//    if err != nil {
	//  log.WithError(err).Error("could not download CVEs from RH API update")
	//  return resp, commonerr.ErrCouldNotDownload
	// }
	// defer r_cve.Body.Close()
	// if !httputil.Status2xx(r_cve) {
	//  log.WithField("StatusCode", r_cesa.StatusCode).Error("Failed to update CentOS CVE db from API")
	//  return resp, commonerr.ErrCouldNotDownload
	// }

	//    r_oval, err := httputil.GetWithUserAgent(ovalURL)
	//    if err != nil {
	//  log.WithError(err).Error("could not download OVALs from RH API update")
	//  return resp, commonerr.ErrCouldNotDownload
	// }
	// defer r_oval.Body.Close()
	// if !httputil.Status2xx(r_oval) {
	//  log.WithField("StatusCode", r_cesa.StatusCode).Error("Failed to update CentOS CESA db")
	//  return resp, commonerr.ErrCouldNotDownload
	// }

	// resp, err = buildResponse(r_cesa.Body, r_cve.Body, r_oval.Body)
	// if err != nil{
	//  return resp, err
	// }

	return resp, nil
}

// func buildResponse(cesaReader io.Reader, cveReader io.Reader, ovalReader io.Reader) (resp vulnsrc.UpdateResponse, err error) {
func buildResponse(cesaReader io.Reader) (resp vulnsrc.UpdateResponse, err error) {

	// Parse CESA into vulnerability db

	log.WithField("package", "CentOS").Info("building response from xml to struct (1)")

	resp_cesa, err_cesa := parseCESA(cesaReader)
	if err_cesa != nil {
		log.WithError(err).Error("could not parse CESA's errata update")
		return resp, commonerr.ErrCouldNotParse
	}

	resp.Vulnerabilities = resp_cesa

	// // Unmarshal CVE JSON
	// // Extract vulnerability data from unmarshalled CVE JSON schema into db
	// resp_cve, err = parseCVEs(cveReader)
	// if err != nil {
	//  log.WithError(err).Error("could not parse CVEs from RH API")
	//  return resp, commonerr.ErrCouldNotParse
	// }
	// resp.Vulnerabilities = append(resp.Vulnerabilities, resp_cve)

	// // Unmarshal OVAL JSON
	// // Extract vulnerability data from unmarshalled OVAL JSON schema
	// resp_oval, err = parseRHSAs(ovalReader)
	// if err != nil {
	//  log.WithError(err).Error("could not parse RHSAs from RH API")
	//  return resp, commonerr.ErrCouldNotParse
	// }
	// resp.Vulnerabilities = append(resp.Vulnerabilities, resp_oval)

	// // var unknownReleases map[string]struct{}
	// // resp.Vulnerabilities, unknownReleases = parseCentOScveJSON(&cves)

	// //combine responses TODOOOOOOO
	return resp, nil
}

func parseCESA(cesaReader io.Reader) (vulnerabilities []database.Vulnerability, err error) {
	log.WithField("package", "CentOS").Info("Parsing CESA xml (2)")

	var cesas CESA
	err = xml.NewDecoder(cesaReader).Decode(&cesas)
	if err != nil {
		log.WithError(err).Error("could not decode CESA's XML")
		return vulnerabilities, commonerr.ErrCouldNotParse
	}
	log.WithField("package", "CentOS").Info("Decoded CESA XML (3)")

	// mvulnerabilities := make(map[string]*database.Vulnerability)

	// Iterate over CESA only and collect any vulnerabilities that affect at least one package
	var vulnName string
	for _, cesa := range cesas.SA {
		if strings.Contains(cesa.Text, "CESA") && len(cesa.Packages) > 0 {
			// get vulnerability name
			vulnName = cesa.Text
			log.WithField("package", "CentOS").Info("aaa THIS IS IMPORTAT (4) : " + vulnName)

			// get package release number?????????/ wtf is this
			
			var vuln database.Vulnerability

			vuln.Name = cesa.Text
			vuln.Link = cesa.References
			vuln.Description = cesa.Description

			
			vuln.Severity = database.UnknownSeverity
			// convertSeverity(cesa.Severity)
			
			

			for _, p := range cesa.Packages {
				log.WithField("package", "CentOS").Info("package: " + p)
				if strings.Compare(strings.ToLower(cesa.Solution), "not available") != 0 {
					vuln.FixedIn = []database.FeatureVersion{
						{
							Feature: database.Feature{
								Namespace: database.Namespace{
									Name:          "centos:" + cesa.OsRelease,
									VersionFormat: rpm.ParserName,
								},
								Name: p,
							},
							Version: versionfmt.MaxVersion,
						},
					}
				}
				// vuln.FixedIn = append(vuln.FixedIn, p)
			}

			vulnerabilities = append(vulnerabilities, vuln)

			
			// //  }
			// // 	// export packages to proper format
			// // 	// determine version of the package that the vulnerability affects
			// // 	var version string
			// // 	var err error
			// // 	// determine fixed version if it exists/is resolved
			// // 	// create and add feature version
			// // 	// store the vulnerability

//////////////////////////////////

		}
	}
	return
}

func parseCVEs(cveReader io.Reader) (vulnerabilities []database.Vulnerability, err error) {
	// var cves CVES
	// err = json.NewDecoder(cveReader).Decode(&cves)
	// if err != nil {
	//  log.WithError(err).Error("could not unmarshal CVE JSON from RH API")
	//  return resp, commonerr.ErrCouldNotParse
	// }

	// mvulnerabilities := make(map[string]*database.Vulnerability)
	// unknownReleases = make(map[string]struct{})

	// for pkgName, pkgNode := range *cves {
	//  for vulnName, vulnNode := range pkgNode {
	//      for releaseName, releaseNode := range vulnNode.Releases {
	//          // Attempt to detect the release number.
	//          if _, isReleaseKnown := database.DebianReleasesMapping[releaseName]; !isReleaseKnown {
	//              unknownReleases[releaseName] = struct{}{}
	//              continue
	//          }

	//          // Skip if the status is not determined or the vulnerability is a temporary one.
	//          // TODO: maybe add "undetermined" as Unknown severity.
	//          if !strings.HasPrefix(vulnName, "CVE-") || releaseNode.Status == "undetermined" {
	//              continue
	//          }

	//          // Get or create the vulnerability.
	//          vulnerability, vulnerabilityAlreadyExists := mvulnerabilities[vulnName]
	//          if !vulnerabilityAlreadyExists {
	//              vulnerability = &database.Vulnerability{
	//                  Vulnerability: database.Vulnerability{
	//                      Name:        vulnName,
	//                      Link:        strings.Join([]string{cveURLPrefix, "/", vulnName}, ""),
	//                      Severity:    database.UnknownSeverity,
	//                      Description: vulnNode.Description,
	//                  },
	//              }
	//          }

	//          // Set the priority of the vulnerability.
	//          // In the JSON, a vulnerability has one urgency per package it affects.
	//          severity := SeverityFromUrgency(releaseNode.Urgency)
	//          if severity.Compare(vulnerability.Severity) > 0 {
	//              // The highest urgency should be the one set.
	//              vulnerability.Severity = severity
	//          }

	//          // Determine the version of the package the vulnerability affects.
	//          var version string
	//          var err error
	//          if releaseNode.Status == "open" {
	//              // Open means that the package is currently vulnerable in the latest
	//              // version of this Debian release.
	//              version = versionfmt.MaxVersion
	//          } else if releaseNode.Status == "resolved" {
	//              // Resolved means that the vulnerability has been fixed in
	//              // "fixed_version" (if affected).
	//              err = versionfmt.Valid(dpkg.ParserName, releaseNode.FixedVersion)
	//              if err != nil {
	//                  log.WithError(err).WithField("version", version).Warning("could not parse package version. skipping")
	//                  continue
	//              }

	//              // FixedVersion = "0" means that the vulnerability affecting
	//              // current feature is not that important
	//              if releaseNode.FixedVersion != "0" {
	//                  version = releaseNode.FixedVersion
	//              }
	//          }

	//          if version == "" {
	//              continue
	//          }

	//          var fixedInVersion string
	//          if version != versionfmt.MaxVersion {
	//              fixedInVersion = version
	//          }

	//          // Create and add the feature version.
	//          pkg := database.AffectedFeature{
	//              FeatureType:     affectedType,
	//              FeatureName:     pkgName,
	//              AffectedVersion: version,
	//              FixedInVersion:  fixedInVersion,
	//              Namespace: database.Namespace{
	//                  Name:          "debian:" + database.DebianReleasesMapping[releaseName],
	//                  VersionFormat: dpkg.ParserName,
	//              },
	//          }
	//          vulnerability.Affected = append(vulnerability.Affected, pkg)

	//          // Store the vulnerability.
	//          mvulnerabilities[vulnName] = vulnerability
	//      }
	//  }
	// }
	// // Convert the vulnerabilities map to a slice
	// for _, v := range mvulnerabilities {
	//  vulnerabilities = append(vulnerabilities, *v)
	// }

	return
}

func parseRHSAs(ovalReader io.Reader) (vulnerabilities []database.Vulnerability, err error) {
	// var rhsas OVAL
	// err = json.NewDecoder(ovalReader).Decode(&rhsas)
	// if err != nil {
	//  log.WithError(err).Error("could not unmarshal RHSA OVAL JSON from RH API")
	//  return resp, commonerr.ErrCouldNotParse
	// }
	return
}

func convertSeverity(sev string) database.Severity {
	switch strings.ToLower(sev) {
	case "n/a":
		return database.NegligibleSeverity
	case "low":
		return database.LowSeverity
	case "moderate":
		return database.MediumSeverity
	case "important", "high": // some ELSAs have "high" instead of "important"
		return database.HighSeverity
	case "critical":
		return database.CriticalSeverity
	default:
		log.WithField("severity", sev).Warning("could not determine vulnerability severity")
		return database.UnknownSeverity
	}
}
