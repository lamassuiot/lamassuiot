package utils

func SliceInsert[E any](array []E, value E, index int) []E {
	return append(array[:index], append([]E{value}, array[index:]...)...)
}

func SliceRemove[E any](array []E, index int) []E {
	return append(array[:index], array[index+1:]...)
}

func SliceMove[E any](array []E, srcIndex int, dstIndex int) []E {
	value := array[srcIndex]
	return SliceInsert(SliceRemove(array, srcIndex), value, dstIndex)
}
