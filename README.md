# radar
A lot of tool using in DevSecOps pipelines. But DevSecOps process does not include secure configuration of this tools. That's why too many misconfigured DevSecOps tools exist on internet. Also so many security tools used for Phishing or Scanning are available on internet with old versions or misconfigured way.

The Radar find DevSecOps or Security tools via Shodan and check their configuration.

Scanned Tools:
- SonarQube
- GoPhish
- OpenVAS (TODO)

# build
```bash
git clone https://github.com/ahmetak4n/radar.git
cd radar
go buid radar.go
```

# usage
Scan misconfigured SonarQube services
<br>
`./radar sonarqube -apiKey $SHODAN_API_KEY` 

Scan Gophish services that work run with default credentials
<br>
`./radar gophish -apiKey $SHODAN_API_KEY` 

# screenshots
![](https://github.com/ahmetak4n/radar/blob/master/sonarqube_how_to.png | width=100)
![gophish_how_to](https://github.com/ahmetak4n/radar/blob/master/gophish_how_to.png)
