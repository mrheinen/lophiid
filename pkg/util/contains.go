package util

// Contains returns true if needle is in search.
func Contains[T comparable](search []T, needle T) bool {
	for _, entry := range search {
		if entry == needle {
			return true
		}
	}
	return false
}
