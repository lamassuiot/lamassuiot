package lms_slices

func UnorderedEqualContent[E any](s1, s2 []E, cmp func(e1, e2 E) bool) bool {
	if len(s1) != len(s2) {
		return false
	}

	for _, e1 := range s1 {
		found := false
		for i := 0; i < len(s2); i++ {
			e2 := s2[i]
			if cmp(e1, e2) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}
