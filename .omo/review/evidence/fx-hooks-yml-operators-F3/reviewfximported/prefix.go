package reviewfximported

import "errors"

var ErrEmpty = errors.New("empty")

func Prefix(s string) string {
	return s + "!"
}
