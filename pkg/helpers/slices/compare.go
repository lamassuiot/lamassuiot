package lms_slices

func UnorderedEqualContent[E any](s1, s2 []E, cmp func(e1, e2 E) bool) bool {
	if len(s1) != len(s2) {
		return false
	}

	for i1, e1 := range s1 {
		found := false
		for i := i1; i < len(s2); i++ {
			e2 := s1[i1]
			if cmp(e1, e2) {
				found = true
			}
		}
		if !found {
			return false
		}
	}

	return true
}
