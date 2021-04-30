package core

import (
	"github.com/fatih/color"
)

func ErrorLog(err error, message string){
	if (err != nil) {
		customColor := color.New(color.Bold, color.FgHiRed).PrintlnFunc()
		message = "[ERROR] " + message
		customColor(message)
		return
	}
}

func WarningLog(message string) {
	customColor := color.New(color.Bold, color.FgHiYellow).PrintlnFunc()
	message = "[WARNING] " + message
	customColor(message)
}

func SuccessLog(message string) {
	customColor := color.New(color.Bold, color.FgGreen).PrintlnFunc()
	message = "[SUCCESS] " + message
	customColor(message)
}

func FailLog(message string) {
	customColor := color.New(color.Bold, color.FgRed).PrintlnFunc()
	message = "[FAIL] " + message
	customColor(message)
}

func PrintBanner(message string){
	customColor := color.New(color.Bold, color.FgHiBlack).PrintlnFunc()
	customColor(message)
}