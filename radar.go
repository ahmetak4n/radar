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
		sonarqube.Menu.Parse(os.Args[2:])
		sonarqube.Scan()
	}
}

func main() { 
	menu()
}
