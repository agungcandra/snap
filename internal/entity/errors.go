package entity

import "errors"

var (
	// ErrNotFound represent error because resource is not exists in server
	ErrNotFound = errors.New("not found")
)
