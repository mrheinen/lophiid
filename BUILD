load("@rules_proto//proto:defs.bzl", "proto_library")
load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
load("@bazel_gazelle//:def.bzl", "gazelle")

gazelle(name = "gazelle")

gazelle(
    name = "gazelle-update-repos",
    args = [
        "-from_file=go.mod",
        "-to_macro=deps.bzl%go_dependencies",
        "-prune",
        "-build_file_proto_mode=disable_global",
    ],
    command = "update-repos",
)

proto_library(
    name = "backend_service_proto",
    srcs = ["backend_service.proto"],
    visibility = ["//visibility:public"],
)

go_proto_library(
    name = "backend_service_go_proto",
    compilers = ["@io_bazel_rules_go//proto:go_grpc"],
    importpath = "/backend_service",
    proto = ":backend_service_proto",
    visibility = ["//visibility:public"],
)

go_library(
    name = "backend_service",
    embed = [":backend_service_go_proto"],
    importpath = "/backend_service",
    visibility = ["//visibility:public"],
)
