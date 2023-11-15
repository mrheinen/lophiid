package analyzer

import "greyhole/backend_service"

type Analyzer interface {
	Analyze(req *backend_service.HttpRequest) (*backend_service.HttpResponse, error)
}
