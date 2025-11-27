package utils

// Ref returns a pointer to the provided value.
func Ref[T any](v T) *T {
	return &v
}

// Deref returns the value the pointer points to or the zero value if nil.
func Deref[T any](v *T) (result T) {
	if v != nil {
		result = *v
	}
	return
}
