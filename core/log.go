package core

import (
	"github.com/fatih/color"
)

func ErrorLog(err error, message string){
	if (err != nil) {
		message = "[ERROR] " + message
		color.Red(message, err)
	}
}

func WarningLog(message string) {
	message = "[WARNING] " + message
	color.Yellow(message)
}