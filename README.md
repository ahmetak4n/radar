[![build](https://github.com/ahmetak4n/radar/actions/workflows/build.yml/badge.svg?branch=master&event=push)](https://github.com/ahmetak4n/radar/actions/workflows/build.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=ahmetak4n_radar&metric=alert_status)](https://sonarcloud.io/dashboard?id=ahmetak4n_radar)

# radar
A lot of tool using in DevSecOps pipelines. But DevSecOps process does not include secure configuration of these tools. That's why too many misconfigured DevSecOps tools exist on internet. Also so many security tools used for Phishing or Scanning are available on internet with old versions or misconfigured way or default credentials.

The Radar find DevSecOps or Security tools via Shodan and check their configuration.

Scanned Tools:
- SonarQube
  - Check default credential
  - Show public projects and details
  - Download source codes from selected project
- GoPhish
  - Check default credential
- OpenVAS (TODO)

# build
```bash
git clone https://github.com/ahmetak4n/radar.git
cd radar
go buid radar.go
```

# usage
Help
<br>
`./radar -h`

Scan misconfigured SonarQube services
<br>
`./radar sonarqube -aK $SHODAN_API_KEY` 

Scan Gophish services that work run with default credentials
<br>
`./radar gophish -aK $SHODAN_API_KEY` 

# screenshots
Find sonarqube services
![sonar_how_to](https://github.com/ahmetak4n/radar/blob/master/sonarqube_how_to.png)

Download source code from detected sonarqube services
![sonar_how_to](https://github.com/ahmetak4n/radar/blob/master/sonarqube_scd_how_to.png)

Find gophish services
![gophish_how_to](https://github.com/ahmetak4n/radar/blob/master/gophish_how_to.png)

# disclaimer
Radar is developed for InfoSec persons. It should be used for authorized testing and/or educational purposes only.
**I take no responsibility for the abuse of Radar**
