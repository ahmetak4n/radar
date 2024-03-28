package utils

import (
	"os"
	"strings"

  "radar/internal/log"
)

func Contains(input string, array []string) (bool) {
	for _, element := range array {
		if (strings.Contains(input, element)){
			return true
		}
	}

	return false
}

func CommonFileExtensions() ([]string) {
	return []string{".java", ".cs", ".py", ".go", ".js", ".html", ".php", ".xml", ".json", ".yml", ".yaml", ".css"}
}

func CreateFolder(path string) (error) {
	err := os.MkdirAll(path, os.ModePerm)
	
	if (err != nil) {
		log.Stdout(log.Error, "An error occured when creating folder", err.Error())
	}

	return err
}

func CreateFile(path string) (*os.File, error) {
	file, err := os.Create(path)
	if (err != nil) {
		log.Stdout(log.Error, "An error occured when creating file", err.Error())
	}

	return file, err
}
