# radar
A lot of tool using in DevSecOps pipelines. But DevSecOps process does not include secure configuration of this tools. That's why too many misconfigured DevSecOps tools exist on internet. Also so many security tools used for Phishing or Scanning are available on internet with old versions or misconfigured way.

The Radar find DevSecOps or Security tools via Shodan and check their configuration.

Scanned Tools:
- SonarQube
- OpenVAS (TODO)
- GoPhish (TODO)

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

![how to](https://github.com/ahmetak4n/radar/blob/master/how_to.png)
