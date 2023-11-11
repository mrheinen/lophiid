#!/bin/sh
#
protoc backend_service.proto --go_out=./ --go-grpc_out=./
