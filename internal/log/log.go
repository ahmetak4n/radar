package log

import (
	"github.com/fatih/color"
)

func Stdout(logType LogType, message string, err string) {
	switch logType {
	case Error:
		if VERBOSE {
			color.Red("[ERROR] " + message + " ::: " + err)
		}
	case Warning:
		color.Yellow("[WARNING] " + message)
	case Success:
		color.Green("[SUCCESS] " + message)
	case Fail:
		color.Red("[FAIL] " + message)
	case Banner:
		color.Blue(message)
	}
}
