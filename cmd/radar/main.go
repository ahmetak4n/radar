package main

import (
	"os"
	"radar/internal/log"
	"radar/internal/scanner"
)

var banner = `
______  ___ ______  ___  ______          ______  
| ___ \/ _ \|  _  \/ _ \ | ___ \        /     . \ 
| |_/ / /_\ \ | | / /_\ \| |_/ /        | .    .| 
|    /|  _  | | | |  _  ||    /         |   .   | 
| |\ \| | | | |/ /| | | || |\ \         |  .  x | 
\_| \_\_| |_/___/ \_| |_/\_| \_|        \_______/ 

`

var menuString = `
Radar has two scanners: sonarqube|gophish
sonarqube
	--m: <search|scan|scd> (default: search)
	
	mode: search
		--search-engine: <shodan|shodan-enterprise|fofa> (default: shodan)
		--api-key: <shodan-api-key> (required)
		--elastic-url: <elastic-url> (required)

	mode: scan
		--elastic-url: <elastic-url> (required)

	mode: scd
		--p: <sonarqube-port> (default: 9000)
		--host: <sonarqube-host> 
		--pK: <sonarqube-project-key>
gophish
	--sE: <shodan|fofa|shodan-enterprise> (default: shodan)
	--aK: <shodan-api-key> (required)
`

func menu() {
	log.Banner(banner)

	if len(os.Args) < 2 {
		log.Warning("Invalid radar scanner. Use '-h' or '--help' for help")
		return
	}

	switch os.Args[1] {
	case "sonarqube":
		sonarqubeMenu(os.Args[2:])
	case "gophish":
		gophishMenu(os.Args[2:])
	case "-h", "--help":
		log.Banner(menuString)
	default:
		log.Warning("Invalid radar scanner. Use `radar -h` for help")
	}
}

func sonarqubeMenu(args []string) {
	sonarqube := scanner.NewSonarqube()

	err := sonarqube.Menu.Parse(args)
	if err != nil {
		log.Error("An error occured when parsing args. Use `radar sonarqube -h` for help", err)
		return
	}

	switch sonarqube.Mode {
	case "search":
		sonarqube.Search()
	case "scan":
		//sonarqube.Scan()
	case "scd":
		//sonarqube.Scd()
	default:
		log.Warning("Invalid `aT`. Use `radar sonarqube -h` for help")
	}
}

func gophishMenu(args []string) {
	/*gophish := gophish.NewGophishScanner()

	err := gophish.Menu.Parse(args)
	if err != nil {
		log.Error("An error occured when parsing args", err)
		return
	}

	gophish.Scan()*/
}

func main() {
	menu()
}
