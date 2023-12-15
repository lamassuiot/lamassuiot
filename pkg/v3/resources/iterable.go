package resources

type Iterator[E any] interface {
	GetList() []E
	GetNextBookmark() string
}

type IterableList[E any] struct {
	NextBookmark string `json:"next"`
	List         []E    `json:"list"`
}

func (itr IterableList[E]) GetList() []E {
	return itr.List
}
func (itr IterableList[E]) GetNextBookmark() string {
	return itr.NextBookmark
}
