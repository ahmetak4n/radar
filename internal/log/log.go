package log

import (
	"github.com/fatih/color"
)

func Banner(message string) {
	color.Magenta(message)
}

func Success(message string) {
	color.Green("[SUCCESS] " + message)
}

func Warning(message string) {
	color.Yellow("[WARNING] " + message)
}

func Fail(message string) {
	color.Red("[FAIL] " + message)
}

func Error(message string, err error) {
	if VERBOSE {
		color.Red()
	}
	color.Red("[ERROR] "+message, err)
}

func ValidationError(message string) {
	color.Red("[VALIDATION ERROR] " + message)
}
