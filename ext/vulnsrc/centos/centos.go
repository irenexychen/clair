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
	"io/ioutil"

	// "encoding/json"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	// "github.com/coreos/clair/ext/versionfmt"
	// "github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/httputil"
)

const (
	cesaURL     = "https://cefs.b-cdn.net/errata.latest.xml"
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
	// var bodyBytes []byte
	data, err := ioutil.ReadAll(r_cesa.Body)
	if err != nil {
		log.WithError(err).Error("could not read body to data")
		return resp, commonerr.ErrCouldNotParse
	}
	// r_cesa.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	// bodyString := string(bodyBytes)
	vs, err := parseCESA(string(data))
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
	log.WithField("package", "CentOS").Info("Parsing CESA xml (2)")

	var cesas CESA

	err = xml.Unmarshal([]byte(cesaData), &cesas)

	if err != nil {
		log.WithError(err).Error("could not decode CESA's XML")
		return vulnerabilities, commonerr.ErrCouldNotParse
	}
	log.WithField("package", "CentOS").Info("Decoded CESA XML (3)")

	for _, sa := range cesas.SA {
		if strings.Contains(sa.XMLName.Local, "CESA") && len(sa.Packages) > 0 {
			var vuln database.Vulnerability

			vuln.Name = sa.XMLName.Local
			vuln.Link = sa.References
			vuln.Description = sa.Description
			vuln.Severity = convertSeverity(sa.Severity)

			for _, pack := range sa.Packages {
				featureVersion := database.FeatureVersion{
					Feature: database.Feature{
						Namespace: database.Namespace{
							Name:          "centos:" + sa.OsArch,
							VersionFormat: rpm.ParserName,
						},
						Name: strings.TrimSpace(pack),
					},
					Version: strings.TrimSpace(pack),
				}
				vuln.FixedIn = append(vuln.FixedIn, featureVersion)
			}

			vulnerabilities = append(vulnerabilities, vuln)
		}
	}
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
