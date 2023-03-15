package helppers

func MergeMaps(m1 *map[string]interface{}, m2 *map[string]interface{}) *map[string]interface{} {
	mout := map[string]interface{}{}
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
