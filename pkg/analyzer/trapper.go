package analyzer

import "greyhole/backend_service"

type TrapperAnalyzer struct {
}

func (p *TrapperAnalyzer) Analyze(req *backend_service.HttpRequest) (*backend_service.HttpResponse, error) {
	r := &backend_service.HttpResponse{}

	return r, nil
}
