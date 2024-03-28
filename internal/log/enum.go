package log

type LogType int

const (
	Error LogType = iota
	Warning
	Success
	Fail
	Banner
)
