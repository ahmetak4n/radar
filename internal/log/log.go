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
	if Verbose {
		color.Red("[ERROR] %s ::: [DETAIL] %s", message, err.Error())
	}
	color.Red("[ERROR] %s", message)
}

func Custom(message string, color *color.Color) {
	color.Println(message)
}
