package helpers

import "maps"

func MergeMaps[E any](m1 *map[string]E, m2 *map[string]E) *map[string]E {
	mout := map[string]E{}
	if m1 != nil {
		maps.Copy(mout, *m1)
	}

	if m2 != nil {
		maps.Copy(mout, *m2)
	}
	return &mout
}
