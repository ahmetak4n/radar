package main

import (
	"os"

	"radar/scanner"

	"radar/core"
)


var	banner =  
`______  ___ ______  ___  ______          ______  
| ___ \/ _ \|  _  \/ _ \ | ___ \        /     . \ 
| |_/ / /_\ \ | | / /_\ \| |_/ /        | .    .| 
|    /|  _  | | | |  _  ||    /         |   .   | 
| |\ \| | | | |/ /| | | || |\ \         |  .  x | 
\_| \_\_| |_/___/ \_| |_/\_| \_|        \_______/ 
`

func menu() {

	core.PrintBanner(banner)

	if (len(os.Args) < 2) {
		core.WarningLog("Please scanner type!")
		return
	}

	switch os.Args[1] {
	case "sonarqube":
		sonarqube := scanner.NewSonarQubeScanner()
		err := sonarqube.Menu.Parse(os.Args[2:])

		core.ErrorLog(err, "An error occured when parsing args")
		
		sonarqube.Scan()
	case "gophish":
		gophish := scanner.NewGophishScanner()
		err := gophish.Menu.Parse(os.Args[2:])

		core.ErrorLog(err, "An error occured when parsing args")

		gophish.Scan()
	}
}

func main() { 
	menu()
}
