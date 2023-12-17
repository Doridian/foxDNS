package generator

type Generator interface {
	Refresh() error
}
