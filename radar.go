package main

import (
	"os"

	"radar/scanner"

	"radar/core"
)

func menu() {
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
