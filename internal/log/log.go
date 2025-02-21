package log

import (
	"github.com/fatih/color"
)

func Banner(message string) {
	color.Magenta(message)
}

func Success(message string) {
	color.Green("[SUCCESS] %s", message)
}

func Warning(message string) {
	color.Yellow("[WARNING] %s", message)
}

func Fail(message string) {
	color.Red("[FAIL] %s", message)
}

func Error(message string, err error) {
	if VERBOSE {
		color.Red("[ERROR] %s ::: [DETAIL] %s", message, err.Error())
	}
	color.Red("[ERROR] %s", message)
}

func ValidationError(message string) {
	color.Red("[VALIDATION ERROR] %s", message)
}
