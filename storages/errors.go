package storages

import "github.com/pkg/errors"

var (
	ErrInvalidToken          = errors.New("invalid token received")
	ErrTokenNotOwnedBySender = errors.New("can`t identify sender as token owner")
)
