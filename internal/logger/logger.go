package logger

import (
	"errors"
	"os"

	"github.com/notaryproject/notation-go/plugin/proto"
)

func Log(filename string, data string) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("logging error: " + err.Error()),
		}
	}
	_, err = f.WriteString(data)

	if err != nil {
		return proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("logging error: " + err.Error()),
		}
	}
	f.Close()
	return nil
}

func LogBytes(filename string, data []byte) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("logging error: " + err.Error()),
		}
	}
	_, err = f.Write(data)

	if err != nil {
		return proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("logging error: " + err.Error()),
		}
	}
	f.Close()
	return nil
}
