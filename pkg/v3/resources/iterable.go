package resources

type Iterator[E any] interface {
	GetList() []*E
	GetNextBookmark() string
}

type IterbaleList[E any] struct {
	NextBookmark string `json:"next"`
	List         []*E   `json:"list"`
}

func (itr *IterbaleList[E]) GetList() []*E {
	return itr.List
}
func (itr *IterbaleList[E]) GetNextBookmark() string {
	return itr.NextBookmark
}
