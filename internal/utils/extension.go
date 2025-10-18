package utils

import (
	"slices"

	"github.com/piligrimm/tls/spec"
)

func rawExtensionLen(extension spec.Extension) int {
	return 2 + 2 + len(extension.Opaque)
}

func RawExtensionsLen(extensions []spec.Extension) int {
	extensionsSum := 0
	for _, extension := range extensions {
		extensionsSum += rawExtensionLen(extension)
	}

	return extensionsSum
}

func CopyExtensions(src []spec.Extension) []spec.Extension {
	dst := make([]spec.Extension, len(src))
	for i, extSrc := range src {
		opaque := CopySlice(extSrc.Opaque)
		dst[i] = spec.Extension{
			Type:   extSrc.Type,
			Opaque: opaque,
		}
	}

	slices.SortFunc(dst, func(a, b spec.Extension) int {
		switch {
		case a.Type < b.Type:
			return -1
		case a.Type > b.Type:
			return 1
		default:
			return 0
		}
	})
	return dst
}
