package responder

type ResponderManager struct {
}

func (r *ResponderManager) GetResponderForType(resType string) *Responder {

	switch resType {

	default:
		return nil
	}
}
