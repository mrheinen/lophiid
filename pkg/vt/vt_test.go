package vt

import (
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"
)

// RoundTripFunc .
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip .
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func NewTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(fn),
	}
}

func TestCheckIP(t *testing.T) {

	requestCount := 0
	testBody := []byte(`
	{
  "data": {
    "id": "8.8.8.8",
    "type": "ip_address",
    "links": {
      "self": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
    },
    "attributes": {
      "last_analysis_date": 1709345008,
      "network": "8.8.8.0/24",
      "last_modification_date": 1709387706,
      "last_https_certificate_date": 1709345309,
      "last_https_certificate": {
        "public_key": {
          "rsa": {
            "key_size": 2048,
            "modulus": "b24a372baa6082a1786aeb3532e8c1bb5cae235b7e62a3349cf8561cf718a70286cf58ce8ebb0f3034e12ded523a71994f064426b44be2f3d78c8efb25c68ec6ddc2ca38277a24f44c7346a5f8fcf4d4d8026adef2294e38e6251ab0a8461cdfdefa17c25fada51dcf320464a3b226b47c209a4913d945ef0c5c8ba986bde90ccdd071f3fa4cbf63b06ab594fece092af207fe802e6b283aa2fff9e097970ef8c46ec68bb2fe3ef8294afaff189fa3eecb44b623455d80c4d31c61d855bcd312c0a0219b0b2012a80f49eec61e48c69577c1951ea1fec0a82e38ca6c676de4649e086d90650aedd8baef2685026176eaefb319b8f84e45ee525797d784d6cd01",
            "exponent": "10001"
          },
          "algorithm": "RSA"
        },
        "thumbprint_sha256": "bf5c58677b98d13f69b286cf66dc4929ffdce274e6fd2ecfac9b2db097ddd7ac",
        "thumbprint": "96d381f9998f30abb96dcb0ff286392d54ff3a57",
        "subject": {
          "CN": "dns.google"
        },
        "validity": {
          "not_after": "2024-04-29 08:19:56",
          "not_before": "2024-02-05 08:19:57"
        },
        "version": "V3",
        "extensions": {
          "certificate_policies": [
            "2.23.140.1.2.1",
            "1.3.6.1.4.1.11129.2.5.3"
          ],
          "extended_key_usage": [
            "serverAuth"
          ],
          "authority_key_identifier": {
            "keyid": "8a747faf85cdee95cd3d9cd0e24614f371351d27"
          },
          "subject_alternative_name": [
            "dns.google",
            "dns.google.com",
            "*.dns.google.com",
            "8888.google",
            "dns64.dns.google",
            "8.8.8.8",
            "8.8.4.4",
            "2001:4860:4860::8888",
            "2001:4860:4860::8844",
            "2001:4860:4860::6464",
            "2001:4860:4860::64"
          ],
          "subject_key_identifier": "3864a320693a77e2e113cc2d9de58dae8170526d",
          "crl_distribution_points": [
            "http://crls.pki.goog/gts1c3/QOvJ0N1sT2A.crl"
          ],
          "key_usage": [
            "digitalSignature",
            "keyEncipherment"
          ],
          "1.3.6.1.4.1.11129.2.4.2": "0481f300f1007600dab6bf6b3fb5b6229f9bc2bb5c6be87091716cbb51848534",
          "CA": false,
          "ca_information_access": {
            "CA Issuers": "http://pki.goog/repo/certs/gts1c3.der",
            "OCSP": "http://ocsp.pki.goog/gts1c3"
          }
        },
        "cert_signature": {
          "signature": "3a62dc253bb53794c8f3639aa7637f3e79be100f881212b35be93d1f60af6e1b329a6a67fe2eb05dee763c870a51e6cbee2287011ab70893083c333b1b0a8c9a987dd36ec7c18d78dd05af2c46567922791770752c7109ffc12d93efc24ad07cac8a7c1ea81910152af1861657f3e8ce6896e5749d5a4c0b253b6d5d34a8483a5e05fcc1415a11fff43929f659286bd9fadca395a4d9a1aeaef08a500c483e311134d3ece6e1b962602bd9282b17c6cb7d9ba861346720fc1f85dd4b243dca2b449c74e69b498ea7a5725460d76f40a045e6b66bec25bf7ded3159fbdb92d714da1d09195c5c4f7e54dac0c843b1071c1654ee92c503bca2db0ded9b0e6a2e59",
          "signature_algorithm": "sha256RSA"
        },
        "serial_number": "58d9f0308a2421d00a4955469dad25ec",
        "issuer": {
          "C": "US",
          "CN": "GTS CA 1C3",
          "O": "Google Trust Services LLC"
        },
        "size": 1511
      },
      "whois_date": 1707741931,
      "whois": "NetRange: 8.8.8.0 - 8.8.8.255\nCIDR: 8.8.8.0/24\nNetName: GOGL\nNetHandle: NET-8-8-8-0-2\nParent: NET8 (NET-8-0-0-0-0)\nNetType: Direct Allocation\nOriginAS: \nOrganization: Google LLC (GOGL)\nRegDate: 2023-12-28\nUpdated: 2023-12-28\nRef: https://rdap.arin.net/registry/ip/8.8.8.0\nOrgName: Google LLC\nOrgId: GOGL\nAddress: 1600 Amphitheatre Parkway\nCity: Mountain View\nStateProv: CA\nPostalCode: 94043\nCountry: US\nRegDate: 2000-03-30\nUpdated: 2019-10-31\nComment: Please note that the recommended way to file abuse complaints are located in the following links. \nComment: \nComment: To report abuse and illegal activity: https://www.google.com/contact/\nComment: \nComment: For legal requests: http://support.google.com/legal \nComment: \nComment: Regards, \nComment: The Google Team\nRef: https://rdap.arin.net/registry/entity/GOGL\nOrgTechHandle: ZG39-ARIN\nOrgTechName: Google LLC\nOrgTechPhone: +1-650-253-0000 \nOrgTechEmail: arin-contact@google.com\nOrgTechRef: https://rdap.arin.net/registry/entity/ZG39-ARIN\nOrgAbuseHandle: ABUSE5250-ARIN\nOrgAbuseName: Abuse\nOrgAbusePhone: +1-650-253-0000 \nOrgAbuseEmail: network-abuse@google.com\nOrgAbuseRef: https://rdap.arin.net/registry/entity/ABUSE5250-ARIN\n",
      "regional_internet_registry": "ARIN",
      "last_analysis_results": {
        "Acronis": {
          "method": "blacklist",
          "engine_name": "Acronis",
          "category": "harmless",
          "result": "clean"
        },
        "0xSI_f33d": {
          "method": "blacklist",
          "engine_name": "0xSI_f33d",
          "category": "undetected",
          "result": "unrated"
        },
        "Abusix": {
          "method": "blacklist",
          "engine_name": "Abusix",
          "category": "harmless",
          "result": "clean"
        },
        "ADMINUSLabs": {
          "method": "blacklist",
          "engine_name": "ADMINUSLabs",
          "category": "harmless",
          "result": "clean"
        },
        "Criminal IP": {
          "method": "blacklist",
          "engine_name": "Criminal IP",
          "category": "harmless",
          "result": "clean"
        },
        "AILabs (MONITORAPP)": {
          "method": "blacklist",
          "engine_name": "AILabs (MONITORAPP)",
          "category": "harmless",
          "result": "clean"
        },
        "AlienVault": {
          "method": "blacklist",
          "engine_name": "AlienVault",
          "category": "harmless",
          "result": "clean"
        },
        "alphaMountain.ai": {
          "method": "blacklist",
          "engine_name": "alphaMountain.ai",
          "category": "harmless",
          "result": "clean"
        },
        "AlphaSOC": {
          "method": "blacklist",
          "engine_name": "AlphaSOC",
          "category": "undetected",
          "result": "unrated"
        },
        "Antiy-AVL": {
          "method": "blacklist",
          "engine_name": "Antiy-AVL",
          "category": "harmless",
          "result": "clean"
        },
        "ArcSight Threat Intelligence": {
          "method": "blacklist",
          "engine_name": "ArcSight Threat Intelligence",
          "category": "malicious",
          "result": "malware"
        },
        "AutoShun": {
          "method": "blacklist",
          "engine_name": "AutoShun",
          "category": "undetected",
          "result": "unrated"
        },
        "Avira": {
          "method": "blacklist",
          "engine_name": "Avira",
          "category": "harmless",
          "result": "clean"
        },
        "benkow.cc": {
          "method": "blacklist",
          "engine_name": "benkow.cc",
          "category": "harmless",
          "result": "clean"
        },
        "Bfore.Ai PreCrime": {
          "method": "blacklist",
          "engine_name": "Bfore.Ai PreCrime",
          "category": "harmless",
          "result": "clean"
        },
        "BitDefender": {
          "method": "blacklist",
          "engine_name": "BitDefender",
          "category": "harmless",
          "result": "clean"
        },
        "Bkav": {
          "method": "blacklist",
          "engine_name": "Bkav",
          "category": "undetected",
          "result": "unrated"
        },
        "Blueliv": {
          "method": "blacklist",
          "engine_name": "Blueliv",
          "category": "harmless",
          "result": "clean"
        },
        "Certego": {
          "method": "blacklist",
          "engine_name": "Certego",
          "category": "harmless",
          "result": "clean"
        },
        "Chong Lua Dao": {
          "method": "blacklist",
          "engine_name": "Chong Lua Dao",
          "category": "harmless",
          "result": "clean"
        },
        "CINS Army": {
          "method": "blacklist",
          "engine_name": "CINS Army",
          "category": "harmless",
          "result": "clean"
        },
        "Cluster25": {
          "method": "blacklist",
          "engine_name": "Cluster25",
          "category": "undetected",
          "result": "unrated"
        },
        "CRDF": {
          "method": "blacklist",
          "engine_name": "CRDF",
          "category": "harmless",
          "result": "clean"
        },
        "Snort IP sample list": {
          "method": "blacklist",
          "engine_name": "Snort IP sample list",
          "category": "harmless",
          "result": "clean"
        },
        "CMC Threat Intelligence": {
          "method": "blacklist",
          "engine_name": "CMC Threat Intelligence",
          "category": "harmless",
          "result": "clean"
        },
        "Cyan": {
          "method": "blacklist",
          "engine_name": "Cyan",
          "category": "undetected",
          "result": "unrated"
        },
        "Cyble": {
          "method": "blacklist",
          "engine_name": "Cyble",
          "category": "malicious",
          "result": "malicious"
        },
        "CyRadar": {
          "method": "blacklist",
          "engine_name": "CyRadar",
          "category": "harmless",
          "result": "clean"
        },
        "DNS8": {
          "method": "blacklist",
          "engine_name": "DNS8",
          "category": "harmless",
          "result": "clean"
        },
        "Dr.Web": {
          "method": "blacklist",
          "engine_name": "Dr.Web",
          "category": "harmless",
          "result": "clean"
        },
        "Ermes": {
          "method": "blacklist",
          "engine_name": "Ermes",
          "category": "undetected",
          "result": "unrated"
        },
        "ESET": {
          "method": "blacklist",
          "engine_name": "ESET",
          "category": "harmless",
          "result": "clean"
        },
        "ESTsecurity": {
          "method": "blacklist",
          "engine_name": "ESTsecurity",
          "category": "harmless",
          "result": "clean"
        },
        "EmergingThreats": {
          "method": "blacklist",
          "engine_name": "EmergingThreats",
          "category": "harmless",
          "result": "clean"
        },
        "Emsisoft": {
          "method": "blacklist",
          "engine_name": "Emsisoft",
          "category": "harmless",
          "result": "clean"
        },
        "Forcepoint ThreatSeeker": {
          "method": "blacklist",
          "engine_name": "Forcepoint ThreatSeeker",
          "category": "harmless",
          "result": "clean"
        },
        "Fortinet": {
          "method": "blacklist",
          "engine_name": "Fortinet",
          "category": "harmless",
          "result": "clean"
        },
        "G-Data": {
          "method": "blacklist",
          "engine_name": "G-Data",
          "category": "harmless",
          "result": "clean"
        },
        "Google Safebrowsing": {
          "method": "blacklist",
          "engine_name": "Google Safebrowsing",
          "category": "harmless",
          "result": "clean"
        },
        "GreenSnow": {
          "method": "blacklist",
          "engine_name": "GreenSnow",
          "category": "harmless",
          "result": "clean"
        },
        "Gridinsoft": {
          "method": "blacklist",
          "engine_name": "Gridinsoft",
          "category": "undetected",
          "result": "unrated"
        },
        "Heimdal Security": {
          "method": "blacklist",
          "engine_name": "Heimdal Security",
          "category": "harmless",
          "result": "clean"
        },
        "IPsum": {
          "method": "blacklist",
          "engine_name": "IPsum",
          "category": "harmless",
          "result": "clean"
        },
        "Juniper Networks": {
          "method": "blacklist",
          "engine_name": "Juniper Networks",
          "category": "harmless",
          "result": "clean"
        },
        "K7AntiVirus": {
          "method": "blacklist",
          "engine_name": "K7AntiVirus",
          "category": "harmless",
          "result": "clean"
        },
        "Kaspersky": {
          "method": "blacklist",
          "engine_name": "Kaspersky",
          "category": "undetected",
          "result": "unrated"
        },
        "Lionic": {
          "method": "blacklist",
          "engine_name": "Lionic",
          "category": "harmless",
          "result": "clean"
        },
        "Lumu": {
          "method": "blacklist",
          "engine_name": "Lumu",
          "category": "undetected",
          "result": "unrated"
        },
        "MalwarePatrol": {
          "method": "blacklist",
          "engine_name": "MalwarePatrol",
          "category": "harmless",
          "result": "clean"
        },
        "MalwareURL": {
          "method": "blacklist",
          "engine_name": "MalwareURL",
          "category": "undetected",
          "result": "unrated"
        },
        "Malwared": {
          "method": "blacklist",
          "engine_name": "Malwared",
          "category": "harmless",
          "result": "clean"
        },
        "Netcraft": {
          "method": "blacklist",
          "engine_name": "Netcraft",
          "category": "undetected",
          "result": "unrated"
        },
        "OpenPhish": {
          "method": "blacklist",
          "engine_name": "OpenPhish",
          "category": "harmless",
          "result": "clean"
        },
        "Phishing Database": {
          "method": "blacklist",
          "engine_name": "Phishing Database",
          "category": "harmless",
          "result": "clean"
        },
        "PhishFort": {
          "method": "blacklist",
          "engine_name": "PhishFort",
          "category": "undetected",
          "result": "unrated"
        },
        "PhishLabs": {
          "method": "blacklist",
          "engine_name": "PhishLabs",
          "category": "undetected",
          "result": "unrated"
        },
        "Phishtank": {
          "method": "blacklist",
          "engine_name": "Phishtank",
          "category": "harmless",
          "result": "clean"
        },
        "PREBYTES": {
          "method": "blacklist",
          "engine_name": "PREBYTES",
          "category": "harmless",
          "result": "clean"
        },
        "PrecisionSec": {
          "method": "blacklist",
          "engine_name": "PrecisionSec",
          "category": "undetected",
          "result": "unrated"
        },
        "Quick Heal": {
          "method": "blacklist",
          "engine_name": "Quick Heal",
          "category": "harmless",
          "result": "clean"
        },
        "Quttera": {
          "method": "blacklist",
          "engine_name": "Quttera",
          "category": "harmless",
          "result": "clean"
        },
        "SafeToOpen": {
          "method": "blacklist",
          "engine_name": "SafeToOpen",
          "category": "undetected",
          "result": "unrated"
        },
        "Scantitan": {
          "method": "blacklist",
          "engine_name": "Scantitan",
          "category": "harmless",
          "result": "clean"
        },
        "SCUMWARE.org": {
          "method": "blacklist",
          "engine_name": "SCUMWARE.org",
          "category": "harmless",
          "result": "clean"
        },
        "Seclookup": {
          "method": "blacklist",
          "engine_name": "Seclookup",
          "category": "harmless",
          "result": "clean"
        },
        "SecureBrain": {
          "method": "blacklist",
          "engine_name": "SecureBrain",
          "category": "harmless",
          "result": "clean"
        },
        "Segasec": {
          "method": "blacklist",
          "engine_name": "Segasec",
          "category": "undetected",
          "result": "unrated"
        },
        "SOCRadar": {
          "method": "blacklist",
          "engine_name": "SOCRadar",
          "category": "harmless",
          "result": "clean"
        },
        "Sophos": {
          "method": "blacklist",
          "engine_name": "Sophos",
          "category": "harmless",
          "result": "clean"
        },
        "Spam404": {
          "method": "blacklist",
          "engine_name": "Spam404",
          "category": "harmless",
          "result": "clean"
        },
        "StopForumSpam": {
          "method": "blacklist",
          "engine_name": "StopForumSpam",
          "category": "harmless",
          "result": "clean"
        },
        "Sucuri SiteCheck": {
          "method": "blacklist",
          "engine_name": "Sucuri SiteCheck",
          "category": "harmless",
          "result": "clean"
        },
        "ThreatHive": {
          "method": "blacklist",
          "engine_name": "ThreatHive",
          "category": "harmless",
          "result": "clean"
        },
        "Threatsourcing": {
          "method": "blacklist",
          "engine_name": "Threatsourcing",
          "category": "harmless",
          "result": "clean"
        },
        "Trustwave": {
          "method": "blacklist",
          "engine_name": "Trustwave",
          "category": "harmless",
          "result": "clean"
        },
        "URLhaus": {
          "method": "blacklist",
          "engine_name": "URLhaus",
          "category": "harmless",
          "result": "clean"
        },
        "URLQuery": {
          "method": "blacklist",
          "engine_name": "URLQuery",
          "category": "undetected",
          "result": "unrated"
        },
        "Viettel Threat Intelligence": {
          "method": "blacklist",
          "engine_name": "Viettel Threat Intelligence",
          "category": "harmless",
          "result": "clean"
        },
        "VIPRE": {
          "method": "blacklist",
          "engine_name": "VIPRE",
          "category": "undetected",
          "result": "unrated"
        },
        "VX Vault": {
          "method": "blacklist",
          "engine_name": "VX Vault",
          "category": "harmless",
          "result": "clean"
        },
        "ViriBack": {
          "method": "blacklist",
          "engine_name": "ViriBack",
          "category": "harmless",
          "result": "clean"
        },
        "Webroot": {
          "method": "blacklist",
          "engine_name": "Webroot",
          "category": "harmless",
          "result": "clean"
        },
        "Yandex Safebrowsing": {
          "method": "blacklist",
          "engine_name": "Yandex Safebrowsing",
          "category": "harmless",
          "result": "clean"
        },
        "ZeroCERT": {
          "method": "blacklist",
          "engine_name": "ZeroCERT",
          "category": "harmless",
          "result": "clean"
        },
        "desenmascara.me": {
          "method": "blacklist",
          "engine_name": "desenmascara.me",
          "category": "harmless",
          "result": "clean"
        },
        "malwares.com URL checker": {
          "method": "blacklist",
          "engine_name": "malwares.com URL checker",
          "category": "harmless",
          "result": "clean"
        },
        "securolytics": {
          "method": "blacklist",
          "engine_name": "securolytics",
          "category": "harmless",
          "result": "clean"
        },
        "Xcitium Verdict Cloud": {
          "method": "blacklist",
          "engine_name": "Xcitium Verdict Cloud",
          "category": "undetected",
          "result": "unrated"
        },
        "zvelo": {
          "method": "blacklist",
          "engine_name": "zvelo",
          "category": "undetected",
          "result": "unrated"
        }
      },
      "continent": "NA",
      "last_analysis_stats": {
        "malicious": 2,
        "suspicious": 0,
        "undetected": 21,
        "harmless": 66,
        "timeout": 0
      },
      "tags": [],
      "asn": 15169,
      "total_votes": {
        "harmless": 184,
        "malicious": 28
      },
      "jarm": "29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae",
      "as_owner": "GOOGLE",
      "reputation": 520,
      "crowdsourced_context": [
        {
          "source": "ArcSight Threat Intelligence",
          "title": "ThreatFox IOCs for 2023-09-10",
          "details": "AsyncRAT botnet C2 server (confidence level: 100%)",
          "severity": "medium",
          "timestamp": 1694383565
        }
      ],
      "country": "US"
    }
  }
}
`)

	client := NewTestClient(func(req *http.Request) *http.Response {
		requestCount += 1
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString(string(testBody))),
			// Must be set to non-nil value or it panics
		}
	})

	// First call should result in an HTTP request, the second will be served from
	// cache.
	vtClient := NewVTClient("ffffffff", time.Hour, client)
	resp, err := vtClient.CheckIP("1.1.1.1")
	if requestCount != 1 {
		t.Errorf("unexpected request count: %d", requestCount)
	}

	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if resp.Data.Attributes.ASN != 15169 {
		t.Errorf("expected %d, got %d", 15169, resp.Data.Attributes.ASN)
	}
	if resp.Data.Attributes.Country != "US" {
		t.Errorf("expected %s, got %s", "US", resp.Data.Attributes.Country)
	}

	// Again. This time we expect no additional request because the response is
	// served from cache.
	resp, _ = vtClient.CheckIP("1.1.1.1")
	if requestCount != 1 {
		t.Errorf("unexpected request count: %d", requestCount)
	}
}

func TestSubmitFile(t *testing.T) {
	testBody := []byte(`
	{
    "data": {
        "type": "analysis",
        "id": "OWY0YzZmNzUwYjgzYTFlYTJkZjRkNTg3ZTJmOTIyM2U6MTcwOTM4ODk1MA==",
        "links": {
            "self": "https://www.virustotal.com/api/v3/analyses/OWY0YzZmNzUwYjgzYTFlYTJkZjRkNTg3ZTJmOTIyM2U6MTcwOTM4ODk1MA=="
        }
    }
}
`)

	client := NewTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString(string(testBody))),
		}
	})

	vtClient := NewVTClient("ffffffff", time.Hour, client)
	resp, err := vtClient.SubmitFile("/dev/null")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if resp.Data.ID != "OWY0YzZmNzUwYjgzYTFlYTJkZjRkNTg3ZTJmOTIyM2U6MTcwOTM4ODk1MA==" {
		t.Error("did not find ID")
	}

}

func TestGetFileAnalysis(t *testing.T) {
	testBody := []byte(`
	{
  "data": {
    "id": "f-8155234d9990da2af43d98d4e6f4df193788fce0d9af20da302363d1d981d3b9-1709458555",
    "type": "analysis",
    "links": {
      "self": "https://www.virustotal.com/api/v3/analyses/f-8155234d9990da2af43d98d4e6f4df193788fce0d9af20da302363d1d981d3b9-1709458555",
      "item": "https://www.virustotal.com/api/v3/files/8155234d9990da2af43d98d4e6f4df193788fce0d9af20da302363d1d981d3b9"
    },
    "attributes": {
      "date": 1709458555,
      "results": {
        "Bkav": {
          "method": "blacklist",
          "engine_name": "Bkav",
          "engine_version": "2.0.0.1",
          "engine_update": "20240303",
          "category": "undetected",
          "result": null
        },
        "Lionic": {
          "method": "blacklist",
          "engine_name": "Lionic",
          "engine_version": "7.5",
          "engine_update": "20240303",
          "category": "undetected",
          "result": null
        },
        "DrWeb": {
          "method": "blacklist",
          "engine_name": "DrWeb",
          "engine_version": "7.0.62.1180",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Linux.DownLoader.9999"
        },
        "ClamAV": {
          "method": "blacklist",
          "engine_name": "ClamAV",
          "engine_version": "1.3.0.0",
          "engine_update": "20240302",
          "category": "undetected",
          "result": null
        },
        "FireEye": {
          "method": "blacklist",
          "engine_name": "FireEye",
          "engine_version": "35.47.0.0",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Generic.Linux.Medusa.C.D64FD9E4"
        },
        "CAT-QuickHeal": {
          "method": "blacklist",
          "engine_name": "CAT-QuickHeal",
          "engine_version": "22.00",
          "engine_update": "20240302",
          "category": "undetected",
          "result": null
        },
        "Skyhigh": {
          "method": "blacklist",
          "engine_name": "Skyhigh",
          "engine_version": "v2021.2.0+4045",
          "engine_update": "20240302",
          "category": "malicious",
          "result": "Linux/Downloader.k"
        },
        "McAfee": {
          "method": "blacklist",
          "engine_name": "McAfee",
          "engine_version": "6.0.6.653",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Linux/Downloader.k"
        },
        "Malwarebytes": {
          "method": "blacklist",
          "engine_name": "Malwarebytes",
          "engine_version": "4.5.5.54",
          "engine_update": "20240303",
          "category": "undetected",
          "result": null
        },
        "Zillya": {
          "method": "blacklist",
          "engine_name": "Zillya",
          "engine_version": "2.0.0.5062",
          "engine_update": "20240301",
          "category": "undetected",
          "result": null
        },
        "Sangfor": {
          "method": "blacklist",
          "engine_name": "Sangfor",
          "engine_version": "2.23.0.0",
          "engine_update": "20240227",
          "category": "malicious",
          "result": "Virus.Generic-Script.Save.ba1"
        },
        "K7AntiVirus": {
          "method": "blacklist",
          "engine_name": "K7AntiVirus",
          "engine_version": "12.145.51250",
          "engine_update": "20240303",
          "category": "undetected",
          "result": null
        },
        "K7GW": {
          "method": "blacklist",
          "engine_name": "K7GW",
          "engine_version": "12.145.51250",
          "engine_update": "20240303",
          "category": "undetected",
          "result": null
        },
        "Arcabit": {
          "method": "blacklist",
          "engine_name": "Arcabit",
          "engine_version": "2022.0.0.18",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Generic.Linux.Medusa.C.D64FD9E4"
        },
        "BitDefenderTheta": {
          "method": "blacklist",
          "engine_name": "BitDefenderTheta",
          "engine_version": "7.2.37796.0",
          "engine_update": "20240202",
          "category": "undetected",
          "result": null
        },
        "VirIT": {
          "method": "blacklist",
          "engine_name": "VirIT",
          "engine_version": "9.5.652",
          "engine_update": "20240301",
          "category": "malicious",
          "result": "Linux.DownLoader.ZO"
        },
        "Symantec": {
          "method": "blacklist",
          "engine_name": "Symantec",
          "engine_version": "1.21.0.0",
          "engine_update": "20240302",
          "category": "malicious",
          "result": "Downloader.Trojan"
        },
        "ESET-NOD32": {
          "method": "blacklist",
          "engine_name": "ESET-NOD32",
          "engine_version": "28831",
          "engine_update": "20240302",
          "category": "malicious",
          "result": "Linux/TrojanDownloader.SH.S"
        },
        "TrendMicro-HouseCall": {
          "method": "blacklist",
          "engine_name": "TrendMicro-HouseCall",
          "engine_version": "10.0.0.1040",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "ELF_MIRAILOD.SM"
        },
        "Avast": {
          "method": "blacklist",
          "engine_name": "Avast",
          "engine_version": "23.9.8494.0",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "BV:Downloader-AAN [Drp]"
        },
        "Cynet": {
          "method": "blacklist",
          "engine_name": "Cynet",
          "engine_version": "4.0.0.29",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Malicious (score: 99)"
        },
        "Kaspersky": {
          "method": "blacklist",
          "engine_name": "Kaspersky",
          "engine_version": "22.0.1.28",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "HEUR:Trojan-Downloader.Shell.Agent.p"
        },
        "BitDefender": {
          "method": "blacklist",
          "engine_name": "BitDefender",
          "engine_version": "7.2",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Generic.Linux.Medusa.C.D64FD9E4"
        },
        "NANO-Antivirus": {
          "method": "blacklist",
          "engine_name": "NANO-Antivirus",
          "engine_version": "1.0.146.25796",
          "engine_update": "20240302",
          "category": "malicious",
          "result": "Trojan.Script.Downloader.hjbjdt"
        },
        "ViRobot": {
          "method": "blacklist",
          "engine_name": "ViRobot",
          "engine_version": "2014.3.20.0",
          "engine_update": "20240302",
          "category": "undetected",
          "result": null
        },
        "MicroWorld-eScan": {
          "method": "blacklist",
          "engine_name": "MicroWorld-eScan",
          "engine_version": "14.0.409.0",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Generic.Linux.Medusa.C.D64FD9E4"
        },
        "Rising": {
          "method": "blacklist",
          "engine_name": "Rising",
          "engine_version": "25.0.0.27",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Downloader.Agent/BASH!1.DB4B (CLASSIC)"
        },
        "Sophos": {
          "method": "blacklist",
          "engine_name": "Sophos",
          "engine_version": "2.4.3.0",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Linux/Dldr-VH"
        },
        "F-Secure": {
          "method": "blacklist",
          "engine_name": "F-Secure",
          "engine_version": "18.10.1547.307",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Malware.HTML/ExpKit.Gen2"
        },
        "Baidu": {
          "method": "blacklist",
          "engine_name": "Baidu",
          "engine_version": "1.0.0.2",
          "engine_update": "20190318",
          "category": "undetected",
          "result": null
        },
        "VIPRE": {
          "method": "blacklist",
          "engine_name": "VIPRE",
          "engine_version": "6.0.0.35",
          "engine_update": "20240302",
          "category": "malicious",
          "result": "Generic.Linux.Medusa.C.D64FD9E4"
        },
        "TrendMicro": {
          "method": "blacklist",
          "engine_name": "TrendMicro",
          "engine_version": "11.0.0.1006",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "ELF_MIRAILOD.SM"
        },
        "CMC": {
          "method": "blacklist",
          "engine_name": "CMC",
          "engine_version": "2.4.2022.1",
          "engine_update": "20240129",
          "category": "undetected",
          "result": null
        },
        "Emsisoft": {
          "method": "blacklist",
          "engine_name": "Emsisoft",
          "engine_version": "2022.6.0.32461",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Generic.Linux.Medusa.C.D64FD9E4 (B)"
        },
        "Jiangmin": {
          "method": "blacklist",
          "engine_name": "Jiangmin",
          "engine_version": "16.0.100",
          "engine_update": "20240302",
          "category": "undetected",
          "result": null
        },
        "Varist": {
          "method": "blacklist",
          "engine_name": "Varist",
          "engine_version": "6.5.1.2",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "SH/Mirai.A.gen!Camelot"
        },
        "Avira": {
          "method": "blacklist",
          "engine_name": "Avira",
          "engine_version": "8.3.3.16",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "HTML/ExpKit.Gen2"
        },
        "MAX": {
          "method": "blacklist",
          "engine_name": "MAX",
          "engine_version": "2023.1.4.1",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "malware (ai score=83)"
        },
        "Antiy-AVL": {
          "method": "blacklist",
          "engine_name": "Antiy-AVL",
          "engine_version": "3.0",
          "engine_update": "20240303",
          "category": "undetected",
          "result": null
        },
        "Kingsoft": {
          "method": "blacklist",
          "engine_name": "Kingsoft",
          "engine_version": "None",
          "engine_update": "20230906",
          "category": "undetected",
          "result": null
        },
        "Gridinsoft": {
          "method": "blacklist",
          "engine_name": "Gridinsoft",
          "engine_version": "1.0.168.174",
          "engine_update": "20240303",
          "category": "undetected",
          "result": null
        },
        "Xcitium": {
          "method": "blacklist",
          "engine_name": "Xcitium",
          "engine_version": "36489",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "TrojWare.Script.TrojanDownloader.Agent.SH@7q1bln"
        },
        "Microsoft": {
          "method": "blacklist",
          "engine_name": "Microsoft",
          "engine_version": "1.1.24010.10",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "TrojanDownloader:Linux/Morila!MTB"
        },
        "SUPERAntiSpyware": {
          "method": "blacklist",
          "engine_name": "SUPERAntiSpyware",
          "engine_version": "5.6.0.1032",
          "engine_update": "20240303",
          "category": "undetected",
          "result": null
        },
        "ZoneAlarm": {
          "method": "blacklist",
          "engine_name": "ZoneAlarm",
          "engine_version": "1.0",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "HEUR:Trojan-Downloader.Shell.Agent.p"
        },
        "GData": {
          "method": "blacklist",
          "engine_name": "GData",
          "engine_version": "A:25.37485B:27.35140",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Generic.Linux.Medusa.C.D64FD9E4"
        },
        "Google": {
          "method": "blacklist",
          "engine_name": "Google",
          "engine_version": "1709454636",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Detected"
        },
        "AhnLab-V3": {
          "method": "blacklist",
          "engine_name": "AhnLab-V3",
          "engine_version": "3.25.1.10473",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Shell/ElfDownloader.S1"
        },
        "Acronis": {
          "method": "blacklist",
          "engine_name": "Acronis",
          "engine_version": "1.2.0.121",
          "engine_update": "20230828",
          "category": "undetected",
          "result": null
        },
        "VBA32": {
          "method": "blacklist",
          "engine_name": "VBA32",
          "engine_version": "5.0.0",
          "engine_update": "20240301",
          "category": "undetected",
          "result": null
        },
        "ALYac": {
          "method": "blacklist",
          "engine_name": "ALYac",
          "engine_version": "2.0.0.8",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Generic.Linux.Medusa.C.D64FD9E4"
        },
        "TACHYON": {
          "method": "blacklist",
          "engine_name": "TACHYON",
          "engine_version": "2024-03-03.02",
          "engine_update": "20240303",
          "category": "undetected",
          "result": null
        },
        "Zoner": {
          "method": "blacklist",
          "engine_name": "Zoner",
          "engine_version": "2.2.2.0",
          "engine_update": "20240303",
          "category": "undetected",
          "result": null
        },
        "Tencent": {
          "method": "blacklist",
          "engine_name": "Tencent",
          "engine_version": "1.0.0.1",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "Heur:Trojan.Linux.Downloader.e"
        },
        "Yandex": {
          "method": "blacklist",
          "engine_name": "Yandex",
          "engine_version": "5.5.2.24",
          "engine_update": "20240303",
          "category": "undetected",
          "result": null
        },
        "Ikarus": {
          "method": "blacklist",
          "engine_name": "Ikarus",
          "engine_version": "6.3.9.0",
          "engine_update": "20240302",
          "category": "malicious",
          "result": "Trojan-Downloader.Linux.Sh"
        },
        "MaxSecure": {
          "method": "blacklist",
          "engine_name": "MaxSecure",
          "engine_version": "1.0.0.1",
          "engine_update": "20240301",
          "category": "undetected",
          "result": null
        },
        "Fortinet": {
          "method": "blacklist",
          "engine_name": "Fortinet",
          "engine_version": "None",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "BASH/TrojanDownloader.SH!tr"
        },
        "AVG": {
          "method": "blacklist",
          "engine_name": "AVG",
          "engine_version": "23.9.8494.0",
          "engine_update": "20240303",
          "category": "malicious",
          "result": "BV:Downloader-AAN [Drp]"
        },
        "Panda": {
          "method": "blacklist",
          "engine_name": "Panda",
          "engine_version": "4.6.4.2",
          "engine_update": "20240302",
          "category": "undetected",
          "result": null
        },
        "Avast-Mobile": {
          "method": "blacklist",
          "engine_name": "Avast-Mobile",
          "engine_version": "240302-06",
          "engine_update": "20240302",
          "category": "type-unsupported",
          "result": null
        },
        "SymantecMobileInsight": {
          "method": "blacklist",
          "engine_name": "SymantecMobileInsight",
          "engine_version": "2.0",
          "engine_update": "20240103",
          "category": "type-unsupported",
          "result": null
        },
        "BitDefenderFalx": {
          "method": "blacklist",
          "engine_name": "BitDefenderFalx",
          "engine_version": "2.0.936",
          "engine_update": "20240128",
          "category": "type-unsupported",
          "result": null
        },
        "Elastic": {
          "method": "blacklist",
          "engine_name": "Elastic",
          "engine_version": "4.0.132",
          "engine_update": "20240223",
          "category": "type-unsupported",
          "result": null
        },
        "DeepInstinct": {
          "method": "blacklist",
          "engine_name": "DeepInstinct",
          "engine_version": "5.0.0.8",
          "engine_update": "20240228",
          "category": "type-unsupported",
          "result": null
        },
        "Webroot": {
          "method": "blacklist",
          "engine_name": "Webroot",
          "engine_version": "1.0.0.403",
          "engine_update": "20240303",
          "category": "type-unsupported",
          "result": null
        },
        "APEX": {
          "method": "blacklist",
          "engine_name": "APEX",
          "engine_version": "6.506",
          "engine_update": "20240301",
          "category": "type-unsupported",
          "result": null
        },
        "Paloalto": {
          "method": "blacklist",
          "engine_name": "Paloalto",
          "engine_version": "0.9.0.1003",
          "engine_update": "20240303",
          "category": "type-unsupported",
          "result": null
        },
        "Alibaba": {
          "method": "blacklist",
          "engine_name": "Alibaba",
          "engine_version": "0.3.0.5",
          "engine_update": "20190527",
          "category": "type-unsupported",
          "result": null
        },
        "Trapmine": {
          "method": "blacklist",
          "engine_name": "Trapmine",
          "engine_version": "4.0.16.96",
          "engine_update": "20240223",
          "category": "type-unsupported",
          "result": null
        },
        "Cylance": {
          "method": "blacklist",
          "engine_name": "Cylance",
          "engine_version": "2.0.0.0",
          "engine_update": "20240208",
          "category": "type-unsupported",
          "result": null
        },
        "SentinelOne": {
          "method": "blacklist",
          "engine_name": "SentinelOne",
          "engine_version": "24.1.0.5",
          "engine_update": "20240129",
          "category": "type-unsupported",
          "result": null
        },
        "tehtris": {
          "method": "blacklist",
          "engine_name": "tehtris",
          "engine_version": "v0.1.4",
          "engine_update": "20240303",
          "category": "type-unsupported",
          "result": null
        },
        "Cybereason": {
          "method": "blacklist",
          "engine_name": "Cybereason",
          "engine_version": "1.2.449",
          "engine_update": "20231102",
          "category": "type-unsupported",
          "result": null
        },
        "Trustlook": {
          "method": "blacklist",
          "engine_name": "Trustlook",
          "engine_version": "1.0",
          "engine_update": "20240303",
          "category": "type-unsupported",
          "result": null
        },
        "CrowdStrike": {
          "method": "blacklist",
          "engine_name": "CrowdStrike",
          "engine_version": "1.0",
          "engine_update": "20231026",
          "category": "type-unsupported",
          "result": null
        }
      },
      "status": "completed",
      "stats": {
        "malicious": 36,
        "suspicious": 0,
        "undetected": 24,
        "harmless": 0,
        "timeout": 0,
        "confirmed-timeout": 0,
        "failure": 0,
        "type-unsupported": 16
      }
    }
  },
  "meta": {
    "file_info": {
      "sha256": "8155234d9990da2af43d98d4e6f4df193788fce0d9af20da302363d1d981d3b9",
      "md5": "00d7c71d4f0478840bc88591afe58c41",
      "sha1": "0977bcb506176be7907f7a697eb0102dedda8ebd",
      "size": 1516
    }
  }
}
`)

	client := NewTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString(string(testBody))),
		}
	})

	vtClient := NewVTClient("ffffffff", time.Hour, client)
	resp, err := vtClient.GetFileAnalysis("ID")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if resp.Data.Attributes.Stats.Malicious != 36 {
		t.Errorf("got %d, expected 36", resp.Data.Attributes.Stats.Malicious)
	}

}
