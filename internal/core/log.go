package core

import (
	"github.com/fatih/color"
)

var (
	VERBOSE = false
)

func CustomLogger(logType string, message string, err string) {
	var c color.Color
	var result string

	switch logType{
	case "error":
		if (VERBOSE) {
			c = *color.New(color.Bold, color.FgHiRed)
			result = "[ERROR] " + message + " ::: " + err
		}
	case "warning":
		c = *color.New(color.Bold, color.FgHiYellow)
		result = "[WARNING] " + message
	case "success":
		c = *color.New(color.Bold, color.FgGreen)
		result = "[SUCCESS] " + message
	case "fail":
		c = *color.New(color.Bold, color.FgRed)
		result = "[FAIL] " + message
	case "banner":
		c = *color.New(color.Bold, color.FgHiBlack)
		result = message
	default:
		return
	}

	cPrint := c.PrintlnFunc()
	cPrint(result)
	c.DisableColor()
}
