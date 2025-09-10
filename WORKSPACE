workspace(name = "loophid")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "f74c98d6df55217a36859c74b460e774abc0410a47cc100d822be34d5f990f16",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.47.1/rules_go-v0.47.1.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.47.1/rules_go-v0.47.1.zip",
    ],
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "b7387f72efb59f876e4daae42f1d3912d0d45563eac7cb23d1de0b094ab588cf",
    url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.34.0/bazel-gazelle-v0.34.0.tar.gz",
)

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "com_google_protobuf",
    sha256 = "616bb3536ac1fff3fb1a141450fa28b875e985712170ea7f1bfe5e5fc41e2cd8",
    strip_prefix = "protobuf-24.4",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v24.4.tar.gz"],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

http_archive(
    name = "rules_proto",
    sha256 = "903af49528dc37ad2adbb744b317da520f133bc1cbbecbdd2a6c546c9ead080b",
    strip_prefix = "rules_proto-6.0.0-rc0",
    url = "https://github.com/bazelbuild/rules_proto/releases/download/6.0.0-rc0/rules_proto-6.0.0-rc0.tar.gz",
)

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")

rules_proto_dependencies()

rules_proto_toolchains()

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")
load("//:deps.bzl", "go_dependencies")

new_local_repository(
    name = "yara_local_lib",
    path = "/usr/local/lib/x86_64-linux-gnu/",
    build_file_content = """
cc_library(
    name = "libs",
    srcs = ["libyara_x_capi.so", "libyara_x.so"],
    visibility = ["//visibility:public"],
)
""",
)

new_local_repository(
    name = "yara_local_hdr",
    path = "/usr/local/include/",
    build_file_content = """

cc_library(
  name = "hdr",
  srcs = ["yara_x.h"],
  visibility = ["//visibility:public"],
)
""",
)




# gazelle:repository_macro deps.bzl%go_dependencies
go_dependencies()

go_rules_dependencies()

go_register_toolchains(version = "1.24.7")

gazelle_dependencies()
