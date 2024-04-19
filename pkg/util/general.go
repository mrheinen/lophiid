package util

import (
	"io/ioutil"
	"reflect"
)

func GetStructName(m interface{}) string {
	if t := reflect.TypeOf(m); t.Kind() == reflect.Ptr {
		return t.Elem().Name()
	} else {
		return t.Name()
	}
}

func ReadFileToString(filePath string) (string, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
