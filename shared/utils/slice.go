package utils

import "github.com/piligrimm/tls/shared/spec"

func CopySlice[T ~byte | spec.CipherSuite](src []T) []T {
	dst := make([]T, len(src))
	copy(dst, src)
	return dst
}
