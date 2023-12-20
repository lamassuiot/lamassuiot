package helpers

func SliceFilter[E any](array []E, filterFunc func(elem E) bool) []E {
	filteredList := []E{}
	for _, elem := range array {
		if filterFunc(elem) {
			filteredList = append(filteredList, elem)
		}
	}

	return filteredList
}
