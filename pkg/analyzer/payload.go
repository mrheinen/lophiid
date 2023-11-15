package analyzer

import "greyhole/backend_service"

type PayloadAnalyzer struct {
}

func (p *PayloadAnalyzer) Analyze(req *backend_service.HttpRequest) (*backend_service.HttpResponse, error) {

	r := &backend_service.HttpResponse{}

	return r, nil
}
