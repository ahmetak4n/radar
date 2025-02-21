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
Radar has two mod: sonarqube|gophish
sonarqube
	-aT: <scan|scd> (Default: scan)
	-sE: <shodan|shodan-enterprise|fofa> (Default: shodan)
	-aK: <shodan-api-key> (Required)

Required when attack-type: scd
	-p: <sonarqube-port> (Default: 9000)
	-host: <sonarqube-host> 
	-pK: <sonarqube-project-key>
gophish
	-sE: <shodan|fofa|shodan-enterprise> (Default: shodan)
	-aK: <shodan-api-key> (Required)
`

func menu() {
	log.Banner(banner)

	if len(os.Args) < 2 {
		log.Warning("Invalid radar mod. Use -h for help")
		return
	}

	switch os.Args[1] {
	case "sonarqube":
		sonarqubeMenu(os.Args[2:])
	case "gophish":
		gophishMenu(os.Args[2:])
	case "-h":
		log.Banner(menuString)
	default:
		log.Warning("Invalid radar mod. Use `radar -h` for help")
	}
}

func sonarqubeMenu(args []string) {
	sonarqube := scanner.NewSonarqube()

	err := sonarqube.Menu.Parse(args)
	if err != nil {
		log.Error("An error occured when parsing args. Use `radar sonarqube -h` for help", err)
		return
	}

	switch sonarqube.AttackType {
	case "scan":
		sonarqube.Scan()
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
