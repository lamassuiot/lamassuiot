package helpers

func MergeMaps[E any](m1 *map[string]E, m2 *map[string]E) *map[string]E {
	mout := map[string]E{}
	if m1 != nil {
		for key, val := range *m1 {
			mout[key] = val
		}
	}

	if m2 != nil {
		for key, val := range *m2 {
			mout[key] = val
		}
	}
	return &mout
}
