package main

import (
	"os"

	"radar/core"
	"radar/scanner"
)


var	banner =  
`______  ___ ______  ___  ______          ______  
| ___ \/ _ \|  _  \/ _ \ | ___ \        /     . \ 
| |_/ / /_\ \ | | / /_\ \| |_/ /        | .    .| 
|    /|  _  | | | |  _  ||    /         |   .   | 
| |\ \| | | | |/ /| | | || |\ \         |  .  x | 
\_| \_\_| |_/___/ \_| |_/\_| \_|        \_______/ 
`

var menuString =
`
Have two mod: sonarqube|gophish
sonarqube
	-attacktype: scan | scd ("scan" used for detect misconfigured sonarqube server (default). "scd" used for download source code from any sonarqube service)
	-apikey: Shodan API Key (Required when attacktype is "scan")
	
`

func menu() {

	core.CustomLogger("banner", banner, "")

	if (len(os.Args) < 2) {
		core.CustomLogger("warning", "Invalid radar mod. Use -h for help", "")
		return
	}

	switch os.Args[1] {
	case "sonarqube":
		sonarqube(os.Args[2:])
	case "gophish":
		gophish(os.Args[2:])
	case "-h":
		core.CustomLogger("banner", menuString, "")
	default:
		core.CustomLogger("warning", "Invalid radar mod. Use `radar -h` for help", "")
	}
}

func sonarqube(args []string) {
	sonarqube := scanner.NewSonarQubeScanner()

	err := sonarqube.Menu.Parse(args)
	if (err != nil) {
		core.CustomLogger("error", "An error occured when parsing args. Use `radar sonarqube -h` for help", err.Error())
		return
	}

	switch sonarqube.AttackType {
	case "scan":
		sonarqube.Scan()
	case "scd":
		sonarqube.Scd()
	default:
		core.CustomLogger("warning", "Invalid `attacktype`. Use `radar sonarqube -h` for help", "")
	}
}

func gophish(args []string) {
	gophish := scanner.NewGophishScanner()

	err := gophish.Menu.Parse(args)
	if (err != nil) {
		core.CustomLogger("error", "An error occured when parsing args", err.Error())
		return
	}

	gophish.Scan()
}

func main() { 
	menu()
}