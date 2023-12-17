package generator

type Generator interface {
	Refresh() error
	Start() error
	Stop() error
}
