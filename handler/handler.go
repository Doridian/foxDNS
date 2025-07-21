package handler

type Handler struct {
	child         Generator
	authoritative bool
}

func New(child Generator, authoritative bool) *Handler {
	hdl := &Handler{
		child:         child,
		authoritative: authoritative,
	}
	return hdl
}
