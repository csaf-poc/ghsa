package utils

func Ref[T any](v T) *T {
	return &v
}

func Deref[T any](v *T) (result T) {
	if v != nil {
		result = *v
	}
	return
}
