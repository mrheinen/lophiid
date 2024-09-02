package javascript

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
)

// Contains helper methods for crypto operations.
type Crypto struct {
}

// Md5sum returns an md5 checksum of the given string.
func (c Crypto) Md5sum(s string) string {
	h := md5.New()
	io.WriteString(h, s)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Sha256sum returns a sha256 checksum of the given string.
func (c Crypto) Sha256sum(s string) string {
	h := sha256.New()
	io.WriteString(h, s)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Sha1sum returns a sha1 checksum of the given string.
func (c Crypto) Sha1sum(s string) string {
	h := sha1.New()
	io.WriteString(h, s)
	return fmt.Sprintf("%x", h.Sum(nil))
}
