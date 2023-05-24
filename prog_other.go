//go:build !windows
// +build !windows

package divert

import "errors"

func SetPath(dllPath string) (err error) {
	return errors.New("not implemented")
}

func SetLib(lib any) error {
	return errors.New("not implemented")
}
