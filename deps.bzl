load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_dependencies():
    go_repository(
        name = "cc_mvdan_xurls_v2",
        build_file_proto_mode = "disable_global",
        importpath = "mvdan.cc/xurls/v2",
        sum = "h1:lyBNOm8Wo71UknhUs4QTFUNNMyxy2JEIaKKo0RWOh+8=",
        version = "v2.5.0",
    )
    go_repository(
        name = "co_honnef_go_tools",
        build_file_proto_mode = "disable_global",
        importpath = "honnef.co/go/tools",
        sum = "h1:/hemPrYIhOhy8zYrNj+069zDB68us2sMGsfkFJO0iZs=",
        version = "v0.0.0-20190523083050-ea95bdfd59fc",
    )
    go_repository(
        name = "com_github_alecthomas_kingpin_v2",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/alecthomas/kingpin/v2",
        sum = "h1:f48lwail6p8zpO1bC4TxtqACaGqHYA22qkHjHpqDjYY=",
        version = "v2.4.0",
    )
    go_repository(
        name = "com_github_alecthomas_units",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/alecthomas/units",
        sum = "h1:t3eaIm0rUkzbrIewtiFmMK5RXHej2XnoXNhxVsAYUfg=",
        version = "v0.0.0-20240626203959-61d1e3462e30",
    )
    go_repository(
        name = "com_github_azure_go_ansiterm",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/Azure/go-ansiterm",
        sum = "h1:UQHMgLO+TxOElx5B5HZ4hJQsoJ/PvUvKRhJHDQXO8P8=",
        version = "v0.0.0-20210617225240-d185dfc1b5a1",
    )
    go_repository(
        name = "com_github_benbjohnson_clock",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/benbjohnson/clock",
        sum = "h1:Q92kusRqC1XV2MjkWETPvjJVqKetz1OzxZB7mHJLju8=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_beorn7_perks",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/beorn7/perks",
        sum = "h1:VlbKKnNfV8bJzeqoa4cOKqO6bYr3WgKZxO8Z16+hsOM=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_github_blang_semver_v4",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/blang/semver/v4",
        sum = "h1:1PFHFE6yCCTv8C1TeyNNarDzntLi7wMI5i/pzqYIsAM=",
        version = "v4.0.0",
    )
    go_repository(
        name = "com_github_burntsushi_toml",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/BurntSushi/toml",
        sum = "h1:WXkYYl6Yr3qBf1K79EBnL4mak0OimBfB0XUf9Vl28OQ=",
        version = "v0.3.1",
    )
    go_repository(
        name = "com_github_cenkalti_backoff_v4",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/cenkalti/backoff/v4",
        sum = "h1:cFAlzYUlVYDysBEH2T5hyJZMh3+5+WCBvSnK6Q8UtC4=",
        version = "v4.1.3",
    )
    go_repository(
        name = "com_github_census_instrumentation_opencensus_proto",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/census-instrumentation/opencensus-proto",
        sum = "h1:iKLQ0xPNFxR/2hzXZMrBo8f1j86j5WHzznCCQxV/b8g=",
        version = "v0.4.1",
    )
    go_repository(
        name = "com_github_cespare_xxhash_v2",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/cespare/xxhash/v2",
        sum = "h1:DC2CZ1Ep5Y4k3ZQ899DldepgrayRUGE6BBZ/cd9Cj44=",
        version = "v2.2.0",
    )
    go_repository(
        name = "com_github_checkpoint_restore_go_criu_v5",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/checkpoint-restore/go-criu/v5",
        sum = "h1:wpFFOoomK3389ue2lAb0Boag6XPht5QYpipxmSNL4d8=",
        version = "v5.3.0",
    )
    go_repository(
        name = "com_github_chromedp_cdproto",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/chromedp/cdproto",
        sum = "h1:aPflPkRFkVwbW6dmcVqfgwp1i+UWGFH6VgR1Jim5Ygc=",
        version = "v0.0.0-20230802225258-3cf4e6d46a89",
    )
    go_repository(
        name = "com_github_chromedp_chromedp",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/chromedp/chromedp",
        sum = "h1:dKtNz4kApb06KuSXoTQIyUC2TrA0fhGDwNZf3bcgfKw=",
        version = "v0.9.2",
    )
    go_repository(
        name = "com_github_chromedp_sysutil",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/chromedp/sysutil",
        sum = "h1:+ZxhTpfpZlmchB58ih/LBHX52ky7w2VhQVKQMucy3Ic=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_chzyer_logex",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/chzyer/logex",
        sum = "h1:+eqR0HfOetur4tgnC8ftU5imRnhi4te+BadWS95c5AM=",
        version = "v1.2.0",
    )
    go_repository(
        name = "com_github_chzyer_readline",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/chzyer/readline",
        sum = "h1:upd/6fQk4src78LMRzh5vItIt361/o4uq553V8B5sGI=",
        version = "v1.5.1",
    )
    go_repository(
        name = "com_github_chzyer_test",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/chzyer/test",
        sum = "h1:dZ0/VyGgQdVGAss6Ju0dt5P0QltE0SFY5Woh6hbIfiQ=",
        version = "v0.0.0-20210722231415-061457976a23",
    )
    go_repository(
        name = "com_github_cilium_ebpf",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/cilium/ebpf",
        sum = "h1:1k/q3ATgxSXRdrmPfH8d7YK0GfqVsEKZAX9dQZvs56k=",
        version = "v0.7.0",
    )
    go_repository(
        name = "com_github_client9_misspell",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/client9/misspell",
        sum = "h1:ta993UF76GwbvJcIo3Y68y/M3WxlpEHPWIGDkJYwzJI=",
        version = "v0.3.4",
    )
    go_repository(
        name = "com_github_cncf_udpa_go",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/cncf/udpa/go",
        sum = "h1:WBZRG4aNOuI15bLRrCgN8fCq8E5Xuty6jGbmSNEvSsU=",
        version = "v0.0.0-20191209042840-269d4d468f6f",
    )
    go_repository(
        name = "com_github_cncf_xds_go",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/cncf/xds/go",
        sum = "h1:jQCWAUqqlij9Pgj2i/PB79y4KOPYVyFYdROxgaCwdTQ=",
        version = "v0.0.0-20231128003011-0fa0005c9caa",
    )
    go_repository(
        name = "com_github_containerd_console",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/containerd/console",
        sum = "h1:lIr7SlA5PxZyMV30bDW0MGbiOPXwc63yRuCP0ARubLw=",
        version = "v1.0.3",
    )
    go_repository(
        name = "com_github_containerd_continuity",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/containerd/continuity",
        sum = "h1:nisirsYROK15TAMVukJOUyGJjz4BNQJBVsNvAXZJ/eg=",
        version = "v0.3.0",
    )
    go_repository(
        name = "com_github_coreos_go_systemd_v22",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/coreos/go-systemd/v22",
        sum = "h1:D9/bQk5vlXQFZ6Kwuu6zaiXJ9oTPe68++AzAJc1DzSI=",
        version = "v22.3.2",
    )
    go_repository(
        name = "com_github_cpuguy83_go_md2man_v2",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/cpuguy83/go-md2man/v2",
        sum = "h1:U+s90UTSYgptZMwQh2aRr3LuazLJIa+Pg3Kc1ylSYVY=",
        version = "v2.0.0-20190314233015-f79a8a8ca69d",
    )
    go_repository(
        name = "com_github_creack_pty",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/creack/pty",
        sum = "h1:07n33Z8lZxZ2qwegKbObQohDhXDQxiMMz1NOUGYlesw=",
        version = "v1.1.11",
    )
    go_repository(
        name = "com_github_cyphar_filepath_securejoin",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/cyphar/filepath-securejoin",
        sum = "h1:YX6ebbZCZP7VkM3scTTokDgBL2TY741X51MTk3ycuNI=",
        version = "v0.2.3",
    )
    go_repository(
        name = "com_github_davecgh_go_spew",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/davecgh/go-spew",
        sum = "h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=",
        version = "v1.1.1",
    )
    go_repository(
        name = "com_github_dlclark_regexp2",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/dlclark/regexp2",
        sum = "h1:+/GIL799phkJqYW+3YbOd8LCcbHzT0Pbo8zl70MHsq0=",
        version = "v1.10.0",
    )
    go_repository(
        name = "com_github_docker_cli",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/docker/cli",
        sum = "h1:eO2KS7ZFeov5UJeaDmIs1NFEDRf32PaqRpvoEkKBy5M=",
        version = "v20.10.17+incompatible",
    )
    go_repository(
        name = "com_github_docker_docker",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/docker/docker",
        sum = "h1:Z6O9Nhsjv+ayUEeI1IojKbYcsGdgYSNqxe1s2MYzUhQ=",
        version = "v20.10.7+incompatible",
    )
    go_repository(
        name = "com_github_docker_go_connections",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/docker/go-connections",
        sum = "h1:El9xVISelRB7BuFusrZozjnkIM5YnzCViNKohAFqRJQ=",
        version = "v0.4.0",
    )
    go_repository(
        name = "com_github_docker_go_units",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/docker/go-units",
        sum = "h1:3uh0PgVws3nIA0Q+MwDC8yjEPf9zjRfZZWXZYDct3Tw=",
        version = "v0.4.0",
    )
    go_repository(
        name = "com_github_dop251_goja",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/dop251/goja",
        sum = "h1:wi6jN5LVt/ljaBG4ue79Ekzb12QfJ52L9Q98tl8SWhw=",
        version = "v0.0.0-20231027120936-b396bb4c349d",
    )
    go_repository(
        name = "com_github_dop251_goja_nodejs",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/dop251/goja_nodejs",
        sum = "h1:W1n4DvpzZGOISgp7wWNtraLcHtnmnTwBlJidqtMIuwQ=",
        version = "v0.0.0-20211022123610-8dd9abb0616d",
    )
    go_repository(
        name = "com_github_envoyproxy_go_control_plane",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/envoyproxy/go-control-plane",
        sum = "h1:4X+VP1GHd1Mhj6IB5mMeGbLCleqxjletLK6K0rbxyZI=",
        version = "v0.12.0",
    )
    go_repository(
        name = "com_github_envoyproxy_protoc_gen_validate",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/envoyproxy/protoc-gen-validate",
        sum = "h1:gVPz/FMfvh57HdSJQyvBtF00j8JU4zdyUgIUNhlgg0A=",
        version = "v1.0.4",
    )
    go_repository(
        name = "com_github_frankban_quicktest",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/frankban/quicktest",
        sum = "h1:8sXhOn0uLys67V8EsXLc6eszDs8VXWxL3iRvebPhedY=",
        version = "v1.11.3",
    )
    go_repository(
        name = "com_github_go_kit_log",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/go-kit/log",
        sum = "h1:MRVx0/zhvdseW+Gza6N9rVzU/IVzaeE1SFI4raAhmBU=",
        version = "v0.2.1",
    )
    go_repository(
        name = "com_github_go_logfmt_logfmt",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/go-logfmt/logfmt",
        sum = "h1:otpy5pqBCBZ1ng9RQ0dPu4PN7ba75Y/aA+UpowDyNVA=",
        version = "v0.5.1",
    )
    go_repository(
        name = "com_github_go_sourcemap_sourcemap",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/go-sourcemap/sourcemap",
        sum = "h1:W1iEw64niKVGogNgBN3ePyLFfuisuzeidWPMPWmECqU=",
        version = "v2.1.3+incompatible",
    )
    go_repository(
        name = "com_github_go_sql_driver_mysql",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/go-sql-driver/mysql",
        sum = "h1:BCTh4TKNUYmOmMUcQ3IipzF5prigylS7XXjEkfCHuOE=",
        version = "v1.6.0",
    )
    go_repository(
        name = "com_github_go_stack_stack",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/go-stack/stack",
        sum = "h1:5SgMzNM5HxrEjV0ww2lTmX6E2Izsfxas4+YHWRs3Lsk=",
        version = "v1.8.0",
    )
    go_repository(
        name = "com_github_go_telegram_bot_api_telegram_bot_api_v5",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/go-telegram-bot-api/telegram-bot-api/v5",
        sum = "h1:wG8n/XJQ07TmjbITcGiUaOtXxdrINDz1b0J1w0SzqDc=",
        version = "v5.5.1",
    )
    go_repository(
        name = "com_github_gobwas_httphead",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/gobwas/httphead",
        sum = "h1:exrUm0f4YX0L7EBwZHuCF4GDp8aJfVeBrlLQrs6NqWU=",
        version = "v0.1.0",
    )
    go_repository(
        name = "com_github_gobwas_pool",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/gobwas/pool",
        sum = "h1:xfeeEhW7pwmX8nuLVlqbzVc7udMDrwetjEv+TZIz1og=",
        version = "v0.2.1",
    )
    go_repository(
        name = "com_github_gobwas_ws",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/gobwas/ws",
        sum = "h1:F2aeBZrm2NDsc7vbovKrWSogd4wvfAxg0FQ89/iqOTk=",
        version = "v1.2.1",
    )
    go_repository(
        name = "com_github_godbus_dbus_v5",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/godbus/dbus/v5",
        sum = "h1:mkgN1ofwASrYnJ5W6U/BxG15eXXXjirgZc7CLqkcaro=",
        version = "v5.0.6",
    )
    go_repository(
        name = "com_github_gogo_protobuf",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/gogo/protobuf",
        sum = "h1:Ov1cvc58UF3b5XjBnZv7+opcTcQFZebYjWzi34vdm4Q=",
        version = "v1.3.2",
    )
    go_repository(
        name = "com_github_golang_glog",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/golang/glog",
        sum = "h1:uCdmnmatrKCgMBlM4rMuJZWOkPDqdbZPnrMXDY4gI68=",
        version = "v1.2.0",
    )
    go_repository(
        name = "com_github_golang_mock",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/golang/mock",
        sum = "h1:G5FRp8JnTd7RQH5kemVNlMeyXQAztQ3mOWV95KxsXH8=",
        version = "v1.1.1",
    )
    go_repository(
        name = "com_github_golang_protobuf",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/golang/protobuf",
        sum = "h1:i7eJL8qZTpSEXOPTxNKhASYpMn+8e5Q6AdndVa1dWek=",
        version = "v1.5.4",
    )
    go_repository(
        name = "com_github_google_go_cmp",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/google/go-cmp",
        sum = "h1:ofyhxvXcZhMsU5ulbFiLKl/XBFqE1GSq7atu8tAmTRI=",
        version = "v0.6.0",
    )
    go_repository(
        name = "com_github_google_pprof",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/google/pprof",
        sum = "h1:dHLYa5D8/Ta0aLR2XcPsrkpAgGeFs6thhMcQK0oQ0n8=",
        version = "v0.0.0-20231229205709-960ae82b1e42",
    )
    go_repository(
        name = "com_github_google_shlex",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/google/shlex",
        sum = "h1:El6M4kTTCOh6aBiKaUGG7oYTSPP8MxqL4YI3kZKwcP4=",
        version = "v0.0.0-20191202100458-e7afc7fbc510",
    )
    go_repository(
        name = "com_github_google_uuid",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/google/uuid",
        sum = "h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=",
        version = "v1.6.0",
    )
    go_repository(
        name = "com_github_gorilla_mux",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/gorilla/mux",
        sum = "h1:TuBL49tXwgrFYWhqrNgrUNEY92u81SPhu7sTdzQEiWY=",
        version = "v1.8.1",
    )
    go_repository(
        name = "com_github_grpc_ecosystem_go_grpc_middleware",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/grpc-ecosystem/go-grpc-middleware",
        sum = "h1:UH//fgunKIs4JdUbpDl1VZCDaL56wXCB/5+wF6uHfaI=",
        version = "v1.4.0",
    )
    go_repository(
        name = "com_github_ianlancetaylor_demangle",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/ianlancetaylor/demangle",
        sum = "h1:BA4a7pe6ZTd9F8kXETBoijjFJ/ntaa//1wiH9BZu4zU=",
        version = "v0.0.0-20230524184225-eabc099b10ab",
    )
    go_repository(
        name = "com_github_imdario_mergo",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/imdario/mergo",
        sum = "h1:b6R2BslTbIEToALKP7LxUvijTsNI9TAe80pLWN2g/HU=",
        version = "v0.3.12",
    )
    go_repository(
        name = "com_github_jackc_pgpassfile",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/jackc/pgpassfile",
        sum = "h1:/6Hmqy13Ss2zCq62VdNG8tM1wchn8zjSGOBJ6icpsIM=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_jackc_pgservicefile",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/jackc/pgservicefile",
        sum = "h1:iCEnooe7UlwOQYpKFhBabPMi4aNAfoODPEFNiAnClxo=",
        version = "v0.0.0-20240606120523-5a60cdf6a761",
    )
    go_repository(
        name = "com_github_jackc_pgx_v5",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/jackc/pgx/v5",
        sum = "h1:x7SYsPBYDkHDksogeSmZZ5xzThcTgRz++I5E+ePFUcs=",
        version = "v5.7.1",
    )
    go_repository(
        name = "com_github_jackc_puddle_v2",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/jackc/puddle/v2",
        sum = "h1:PR8nw+E/1w0GLuRFSmiioY6UooMp6KJv0/61nB7icHo=",
        version = "v2.2.2",
    )
    go_repository(
        name = "com_github_jarcoal_httpmock",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/jarcoal/httpmock",
        sum = "h1:2RJ8GP0IIaWwcC9Fp2BmVi8Kog3v2Hn7VXM3fTd+nuc=",
        version = "v1.3.0",
    )
    go_repository(
        name = "com_github_josharian_intern",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/josharian/intern",
        sum = "h1:vlS4z54oSdjm0bgjRigI+G1HpF+tI+9rE5LLzOg8HmY=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_jpillora_backoff",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/jpillora/backoff",
        sum = "h1:uvFg412JmmHBHw7iwprIxkPMI+sGQ4kzOWsMeHnm2EA=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_json_iterator_go",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/json-iterator/go",
        sum = "h1:PV8peI4a0ysnczrg+LtxykD8LfKY9ML6u2jnxaEnrnM=",
        version = "v1.1.12",
    )
    go_repository(
        name = "com_github_julienschmidt_httprouter",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/julienschmidt/httprouter",
        sum = "h1:U0609e9tgbseu3rBINet9P48AI/D3oJs4dN7jwJOQ1U=",
        version = "v1.3.0",
    )
    go_repository(
        name = "com_github_kisielk_errcheck",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/kisielk/errcheck",
        sum = "h1:e8esj/e4R+SAOwFwN+n3zr0nYeCyeweozKfO23MvHzY=",
        version = "v1.5.0",
    )
    go_repository(
        name = "com_github_kisielk_gotool",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/kisielk/gotool",
        sum = "h1:AV2c/EiW3KqPNT9ZKl07ehoAGi4C5/01Cfbblndcapg=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_kkyr_fig",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/kkyr/fig",
        sum = "h1:4D/g72a8ij1fgRypuIbEoqIT7ukf2URVBtE777/gkbc=",
        version = "v0.4.0",
    )
    go_repository(
        name = "com_github_konsorten_go_windows_terminal_sequences",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/konsorten/go-windows-terminal-sequences",
        sum = "h1:mweAR1A6xJ3oS2pRaGiHgQ4OO8tzTaLawm8vnODuwDk=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_github_kr_pretty",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/kr/pretty",
        sum = "h1:flRD4NNwYAUpkphVc1HcthR4KEIFJ65n8Mw5qdRn3LE=",
        version = "v0.3.1",
    )
    go_repository(
        name = "com_github_kr_pty",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/kr/pty",
        sum = "h1:VkoXIwSboBpnk99O/KFauAEILuNHv5DVFKZMBN/gUgw=",
        version = "v1.1.1",
    )
    go_repository(
        name = "com_github_kr_text",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/kr/text",
        sum = "h1:5Nx0Ya0ZqY2ygV366QzturHI13Jq95ApcVaJBhpS+AY=",
        version = "v0.2.0",
    )
    go_repository(
        name = "com_github_lib_pq",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/lib/pq",
        sum = "h1:YXG7RB+JIjhP29X+OtkiDnYaXQwpS4JEWq7dtCCRUEw=",
        version = "v1.10.9",
    )
    go_repository(
        name = "com_github_mailru_easyjson",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/mailru/easyjson",
        sum = "h1:UGYAvKxe3sBsEDzO8ZeWOSlIQfWFlxbzLZe7hwFURr0=",
        version = "v0.7.7",
    )
    go_repository(
        name = "com_github_microsoft_go_winio",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/Microsoft/go-winio",
        sum = "h1:slsWYD/zyx7lCXoZVlvQrj0hPTM1HI4+v1sIda2yDvg=",
        version = "v0.6.0",
    )
    go_repository(
        name = "com_github_mitchellh_go_homedir",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/mitchellh/go-homedir",
        sum = "h1:lukF9ziXFxDFPkA1vsr5zpc1XuPDn/wFntq5mG+4E0Y=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_mitchellh_mapstructure",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/mitchellh/mapstructure",
        sum = "h1:jeMsZIYE/09sWLaz43PL7Gy6RuMjD2eJVyuac5Z2hdY=",
        version = "v1.5.0",
    )
    go_repository(
        name = "com_github_moby_sys_mountinfo",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/moby/sys/mountinfo",
        sum = "h1:2Ks8/r6lopsxWi9m58nlwjaeSzUX9iiL1vj5qB/9ObI=",
        version = "v0.5.0",
    )
    go_repository(
        name = "com_github_moby_term",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/moby/term",
        sum = "h1:rzf0wL0CHVc8CEsgyygG0Mn9CNCCPZqOPaz8RiiHYQk=",
        version = "v0.0.0-20201216013528-df9cb8a40635",
    )
    go_repository(
        name = "com_github_modern_go_concurrent",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/modern-go/concurrent",
        sum = "h1:TRLaZ9cD/w8PVh93nsPXa1VrQ6jlwL5oN8l14QlcNfg=",
        version = "v0.0.0-20180306012644-bacd9c7ef1dd",
    )
    go_repository(
        name = "com_github_modern_go_reflect2",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/modern-go/reflect2",
        sum = "h1:xBagoLtFs94CBntxluKeaWgTMpvLxC4ur3nMaC9Gz0M=",
        version = "v1.0.2",
    )
    go_repository(
        name = "com_github_mrheinen_magicmime",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/mrheinen/magicmime",
        sum = "h1:B7uMqdZujqJ6EBkepOyzpaVZ2arRtPV2Cso5sHh/vyM=",
        version = "v0.0.0-20240329164816-cbc792827fe4",
    )
    go_repository(
        name = "com_github_mrheinen_p0fclient",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/mrheinen/p0fclient",
        sum = "h1:UsCD/XNDmk+WVYj9by9dFJ6UtwqDGFfumDI3wIag8Oc=",
        version = "v0.0.0-20240415163501-4961d493ae47",
    )
    go_repository(
        name = "com_github_mrunalp_fileutils",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/mrunalp/fileutils",
        sum = "h1:NKzVxiH7eSk+OQ4M+ZYW1K6h27RUV3MI6NUTsHhU6Z4=",
        version = "v0.5.0",
    )
    go_repository(
        name = "com_github_mwitkow_go_conntrack",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/mwitkow/go-conntrack",
        sum = "h1:KUppIJq7/+SVif2QVs3tOP0zanoHgBEVAwHxUSIzRqU=",
        version = "v0.0.0-20190716064945-2f068394615f",
    )
    go_repository(
        name = "com_github_nvveen_gotty",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/Nvveen/Gotty",
        sum = "h1:TngWCqHvy9oXAN6lEVMRuU21PR1EtLVZJmdB18Gu3Rw=",
        version = "v0.0.0-20120604004816-cd527374f1e5",
    )
    go_repository(
        name = "com_github_opencontainers_go_digest",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/opencontainers/go-digest",
        sum = "h1:apOUWs51W5PlhuyGyz9FCeeBIOUDA/6nW8Oi/yOhh5U=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_opencontainers_image_spec",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/opencontainers/image-spec",
        sum = "h1:9yCKha/T5XdGtO0q9Q9a6T5NUCsTn/DrBg0D7ufOcFM=",
        version = "v1.0.2",
    )
    go_repository(
        name = "com_github_opencontainers_runc",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/opencontainers/runc",
        sum = "h1:L44KXEpKmfWDcS02aeGm8QNTFXTo2D+8MYGDIJ/GDEs=",
        version = "v1.1.5",
    )
    go_repository(
        name = "com_github_opencontainers_runtime_spec",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/opencontainers/runtime-spec",
        sum = "h1:3snG66yBm59tKhhSPQrQ/0bCrv1LQbKt40LnUPiUxdc=",
        version = "v1.0.3-0.20210326190908-1c3f411f0417",
    )
    go_repository(
        name = "com_github_opencontainers_selinux",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/opencontainers/selinux",
        sum = "h1:rAiKF8hTcgLI3w0DHm6i0ylVVcOrlgR1kK99DRLDhyU=",
        version = "v1.10.0",
    )
    go_repository(
        name = "com_github_openrdap_rdap",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/openrdap/rdap",
        sum = "h1:Rv6YbanbiVPsKRvOLdUmlU1AL5+2OFuEFLjFN+mQsCM=",
        version = "v0.9.1",
    )
    go_repository(
        name = "com_github_opentracing_opentracing_go",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/opentracing/opentracing-go",
        sum = "h1:pWlfV3Bxv7k65HYwkikxat0+s3pV4bsqf19k25Ur8rU=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_ory_dockertest_v3",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/ory/dockertest/v3",
        sum = "h1:4K3z2VMe8Woe++invjaTB7VRyQXQy5UY+loujO4aNE4=",
        version = "v3.10.0",
    )
    go_repository(
        name = "com_github_pelletier_go_toml_v2",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/pelletier/go-toml/v2",
        sum = "h1:LWAJwfNvjQZCFIDKWYQaM62NcYeYViCmWIwmOStowAI=",
        version = "v2.1.1",
    )
    go_repository(
        name = "com_github_pkg_errors",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/pkg/errors",
        sum = "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
        version = "v0.9.1",
    )
    go_repository(
        name = "com_github_pmezard_go_difflib",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/pmezard/go-difflib",
        sum = "h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_prometheus_client_golang",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/prometheus/client_golang",
        sum = "h1:ygXvpU1AoN1MhdzckN+PyD9QJOSD4x7kmXYlnfbA6JU=",
        version = "v1.19.0",
    )
    go_repository(
        name = "com_github_prometheus_client_model",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/prometheus/client_model",
        sum = "h1:k1v3CzpSRUTrKMppY35TLwPvxHqBu0bYgxZzqGIgaos=",
        version = "v0.6.0",
    )
    go_repository(
        name = "com_github_prometheus_common",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/prometheus/common",
        sum = "h1:YSZE6aa9+luNa2da6/Tik0q0A5AbR+U003TItK57CPQ=",
        version = "v0.50.0",
    )
    go_repository(
        name = "com_github_prometheus_community_pro_bing",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/prometheus-community/pro-bing",
        sum = "h1:Fq+4BUXKIvsPtXUY8K+04ud9dkAuFozqGmRAyNUpffY=",
        version = "v0.5.0",
    )
    go_repository(
        name = "com_github_prometheus_procfs",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/prometheus/procfs",
        sum = "h1:GqzLlQyfsPbaEHaQkO7tbDlriv/4o5Hudv6OXHGKX7o=",
        version = "v0.13.0",
    )
    go_repository(
        name = "com_github_rakyll_magicmime",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/rakyll/magicmime",
        sum = "h1:aFIp1DqgzjcB3FI7rQk6uZl73i1VPpWswab1YKU4CL4=",
        version = "v0.1.0",
    )
    go_repository(
        name = "com_github_rogpeppe_go_internal",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/rogpeppe/go-internal",
        sum = "h1:TMyTOH3F/DB16zRVcYyreMH6GnZZrwQVAoYjRBZyWFQ=",
        version = "v1.10.0",
    )
    go_repository(
        name = "com_github_rs_cors",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/rs/cors",
        sum = "h1:0B9GE/r9Bc2UxRMMtymBkHTenPkHDv0CW4Y98GBY+po=",
        version = "v1.11.0",
    )
    go_repository(
        name = "com_github_russross_blackfriday_v2",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/russross/blackfriday/v2",
        sum = "h1:lPqVAte+HuHNfhJ/0LC98ESWRz8afy9tM/0RK8m9o+Q=",
        version = "v2.0.1",
    )
    go_repository(
        name = "com_github_sashabaranov_go_openai",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/sashabaranov/go-openai",
        sum = "h1:fHv9urGxABfm885xGWsXFSk5cksa+8dJ4jGli/UQQcI=",
        version = "v1.30.0",
    )
    go_repository(
        name = "com_github_seccomp_libseccomp_golang",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/seccomp/libseccomp-golang",
        sum = "h1:RpforrEYXWkmGwJHIGnLZ3tTWStkjVVstwzNGqxX2Ds=",
        version = "v0.9.2-0.20220502022130-f33da4d89646",
    )
    go_repository(
        name = "com_github_shurcool_sanitized_anchor_name",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/shurcooL/sanitized_anchor_name",
        sum = "h1:PdmoCO6wvbs+7yrJyMORt4/BmY5IYyJwS/kOiWx8mHo=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_sirupsen_logrus",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/sirupsen/logrus",
        sum = "h1:dJKuHgqk1NNQlqoA6BTlM1Wf9DOH3NBjQyu0h9+AZZE=",
        version = "v1.8.1",
    )
    go_repository(
        name = "com_github_sourcegraph_conc",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/sourcegraph/conc",
        sum = "h1:OQTbbt6P72L20UqAkXXuLOj79LfEanQ+YQFNpLA9ySo=",
        version = "v0.3.0",
    )
    go_repository(
        name = "com_github_spf13_pflag",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/spf13/pflag",
        sum = "h1:zPAT6CGy6wXeQ7NtTnaTerfKOsV6V6F8agHXFiazDkg=",
        version = "v1.0.3",
    )
    go_repository(
        name = "com_github_stretchr_objx",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/stretchr/objx",
        sum = "h1:xuMeJ0Sdp5ZMRXx/aWO6RZxdr3beISkG5/G/aIRr3pY=",
        version = "v0.5.2",
    )
    go_repository(
        name = "com_github_stretchr_testify",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/stretchr/testify",
        sum = "h1:HtqpIVDClZ4nwg75+f6Lvsy/wHu+3BoSGCbBAcpTsTg=",
        version = "v1.9.0",
    )
    go_repository(
        name = "com_github_syndtr_gocapability",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/syndtr/gocapability",
        sum = "h1:kdXcSzyDtseVEc4yCz2qF8ZrQvIDBJLl4S1c3GCXmoI=",
        version = "v0.0.0-20200815063812-42c35b437635",
    )
    go_repository(
        name = "com_github_urfave_cli",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/urfave/cli",
        sum = "h1:+mkCCcOFKPnCmVYVcURKps1Xe+3zP90gSYGNfRkjoIY=",
        version = "v1.22.1",
    )
    go_repository(
        name = "com_github_vingarcia_ksql",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/vingarcia/ksql",
        sum = "h1:1LVRGW39XPaYltPHNQsvHms+bWHp8e99sxQx+aEXDMQ=",
        version = "v1.12.3",
    )
    go_repository(
        name = "com_github_vingarcia_ksql_adapters_kpgx5",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/vingarcia/ksql/adapters/kpgx5",
        sum = "h1:nNddw2HjfwLb/wN1PA+ks4CLsc6S8vaP0Zgua7Mz9l4=",
        version = "v1.12.3",
    )
    go_repository(
        name = "com_github_virustotal_yara_x_go",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/VirusTotal/yara-x/go",
        sum = "h1:nR7MKfNOOqsLXyeJYjgFOQcCjfME9qAoDLiN2Z7/pcg=",
        version = "v0.12.0",
    )
    go_repository(
        name = "com_github_vishvananda_netlink",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/vishvananda/netlink",
        sum = "h1:1iyaYNBLmP6L0220aDnYQpo1QEV4t4hJ+xEEhhJH8j0=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_vishvananda_netns",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/vishvananda/netns",
        sum = "h1:OviZH7qLw/7ZovXvuNyL3XQl8UFofeikI1NW1Gypu7k=",
        version = "v0.0.0-20191106174202-0a2b9b5464df",
    )
    go_repository(
        name = "com_github_xeipuuv_gojsonpointer",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/xeipuuv/gojsonpointer",
        sum = "h1:J9EGpcZtP0E/raorCMxlFGSTBrsSlaDGf3jU/qvAE2c=",
        version = "v0.0.0-20180127040702-4e3ac2762d5f",
    )
    go_repository(
        name = "com_github_xeipuuv_gojsonreference",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/xeipuuv/gojsonreference",
        sum = "h1:EzJWgHovont7NscjpAxXsDA8S8BMYve8Y5+7cuRE7R0=",
        version = "v0.0.0-20180127040603-bd5ef7bd5415",
    )
    go_repository(
        name = "com_github_xeipuuv_gojsonschema",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/xeipuuv/gojsonschema",
        sum = "h1:LhYJRs+L4fBtjZUfuSZIKGeVu0QRy8e5Xi7D17UxZ74=",
        version = "v1.2.0",
    )
    go_repository(
        name = "com_github_xhit_go_str2duration_v2",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/xhit/go-str2duration/v2",
        sum = "h1:lxklc02Drh6ynqX+DdPyp5pCKLUQpRT8bp8Ydu2Bstc=",
        version = "v2.1.0",
    )
    go_repository(
        name = "com_github_yuin_goldmark",
        build_file_proto_mode = "disable_global",
        importpath = "github.com/yuin/goldmark",
        sum = "h1:fVcFKWvrslecOb/tg+Cc05dkeYx540o0FuFt3nUVDoE=",
        version = "v1.4.13",
    )
    go_repository(
        name = "com_google_cloud_go",
        build_file_proto_mode = "disable_global",
        importpath = "cloud.google.com/go",
        sum = "h1:e0WKqKTd5BnrG8aKH3J3h+QvEIQtSUcf2n5UZ5ZgLtQ=",
        version = "v0.26.0",
    )
    go_repository(
        name = "com_google_cloud_go_compute",
        build_file_proto_mode = "disable_global",
        importpath = "cloud.google.com/go/compute",
        sum = "h1:phWcR2eWzRJaL/kOiJwfFsPs4BaKq1j6vnpZrc1YlVg=",
        version = "v1.24.0",
    )
    go_repository(
        name = "com_google_cloud_go_compute_metadata",
        build_file_proto_mode = "disable_global",
        importpath = "cloud.google.com/go/compute/metadata",
        sum = "h1:mg4jlk7mCAj6xXp9UJ4fjI9VUI5rubuGBW5aJ7UnBMY=",
        version = "v0.2.3",
    )
    go_repository(
        name = "in_gopkg_check_v1",
        build_file_proto_mode = "disable_global",
        importpath = "gopkg.in/check.v1",
        sum = "h1:Hei/4ADfdWqJk1ZMxUNpqntNwaWcugrBjAiHlqqRiVk=",
        version = "v1.0.0-20201130134442-10cb98267c6c",
    )
    go_repository(
        name = "in_gopkg_errgo_v2",
        build_file_proto_mode = "disable_global",
        importpath = "gopkg.in/errgo.v2",
        sum = "h1:0vLT13EuvQ0hNvakwLuFZ/jYrLp5F3kcWHXdRggjCE8=",
        version = "v2.1.0",
    )
    go_repository(
        name = "in_gopkg_yaml_v2",
        build_file_proto_mode = "disable_global",
        importpath = "gopkg.in/yaml.v2",
        sum = "h1:D8xgwECY7CYvx+Y2n4sBz93Jn9JRvxdiyyo8CTfuKaY=",
        version = "v2.4.0",
    )
    go_repository(
        name = "in_gopkg_yaml_v3",
        build_file_proto_mode = "disable_global",
        importpath = "gopkg.in/yaml.v3",
        sum = "h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=",
        version = "v3.0.1",
    )
    go_repository(
        name = "org_golang_google_appengine",
        build_file_proto_mode = "disable_global",
        importpath = "google.golang.org/appengine",
        sum = "h1:IhEN5q69dyKagZPYMSdIjS2HqprW324FRQZJcGqPAsM=",
        version = "v1.6.8",
    )
    go_repository(
        name = "org_golang_google_genproto",
        build_file_proto_mode = "disable_global",
        importpath = "google.golang.org/genproto",
        sum = "h1:F6qOa9AZTYJXOUEr4jDysRDLrm4PHePlge4v4TGAlxY=",
        version = "v0.0.0-20240227224415-6ceb2ff114de",
    )
    go_repository(
        name = "org_golang_google_genproto_googleapis_api",
        build_file_proto_mode = "disable_global",
        importpath = "google.golang.org/genproto/googleapis/api",
        sum = "h1:jFNzHPIeuzhdRwVhbZdiym9q0ory/xY3sA+v2wPg8I0=",
        version = "v0.0.0-20240227224415-6ceb2ff114de",
    )
    go_repository(
        name = "org_golang_google_genproto_googleapis_rpc",
        build_file_proto_mode = "disable_global",
        importpath = "google.golang.org/genproto/googleapis/rpc",
        sum = "h1:DujSIu+2tC9Ht0aPNA7jgj23Iq8Ewi5sgkQ++wdvonE=",
        version = "v0.0.0-20240429193739-8cf5692501f6",
    )
    go_repository(
        name = "org_golang_google_grpc",
        build_file_proto_mode = "disable_global",
        importpath = "google.golang.org/grpc",
        sum = "h1:MUeiw1B2maTVZthpU5xvASfTh3LDbxHd6IJ6QQVU+xM=",
        version = "v1.63.2",
    )
    go_repository(
        name = "org_golang_google_protobuf",
        build_file_proto_mode = "disable_global",
        importpath = "google.golang.org/protobuf",
        sum = "h1:82DV7MYdb8anAVi3qge1wSnMDrnKK7ebr+I0hHRN1BU=",
        version = "v1.36.3",
    )
    go_repository(
        name = "org_golang_x_crypto",
        build_file_proto_mode = "disable_global",
        importpath = "golang.org/x/crypto",
        sum = "h1:ihbySMvVjLAeSH1IbfcRTkD/iNscyz8rGzjF/E5hV6U=",
        version = "v0.31.0",
    )
    go_repository(
        name = "org_golang_x_exp",
        build_file_proto_mode = "disable_global",
        importpath = "golang.org/x/exp",
        sum = "h1:c2HOrn5iMezYjSlGPncknSEr/8x5LELb/ilJbXi9DEA=",
        version = "v0.0.0-20190121172915-509febef88a4",
    )
    go_repository(
        name = "org_golang_x_lint",
        build_file_proto_mode = "disable_global",
        importpath = "golang.org/x/lint",
        sum = "h1:5hukYrvBGR8/eNkX5mdUezrA6JiaEZDtJb9Ei+1LlBs=",
        version = "v0.0.0-20190930215403-16217165b5de",
    )
    go_repository(
        name = "org_golang_x_mod",
        build_file_proto_mode = "disable_global",
        importpath = "golang.org/x/mod",
        sum = "h1:zY54UmvipHiNd+pm+m0x9KhZ9hl1/7QNMyxXbc6ICqA=",
        version = "v0.17.0",
    )
    go_repository(
        name = "org_golang_x_net",
        build_file_proto_mode = "disable_global",
        importpath = "golang.org/x/net",
        sum = "h1:74SYHlV8BIgHIFC/LrYkOGIwL19eTYXQ5wc6TBuO36I=",
        version = "v0.33.0",
    )
    go_repository(
        name = "org_golang_x_oauth2",
        build_file_proto_mode = "disable_global",
        importpath = "golang.org/x/oauth2",
        sum = "h1:09qnuIAgzdx1XplqJvW6CQqMCtGZykZWcXzPMPUusvI=",
        version = "v0.18.0",
    )
    go_repository(
        name = "org_golang_x_sync",
        build_file_proto_mode = "disable_global",
        importpath = "golang.org/x/sync",
        sum = "h1:3NQrjDixjgGwUOCaF8w2+VYHv0Ve/vGYSbdkTa98gmQ=",
        version = "v0.10.0",
    )
    go_repository(
        name = "org_golang_x_sys",
        build_file_proto_mode = "disable_global",
        importpath = "golang.org/x/sys",
        sum = "h1:Fksou7UEQUWlKvIdsqzJmUmCX3cZuD2+P3XyyzwMhlA=",
        version = "v0.28.0",
    )
    go_repository(
        name = "org_golang_x_term",
        build_file_proto_mode = "disable_global",
        importpath = "golang.org/x/term",
        sum = "h1:WP60Sv1nlK1T6SupCHbXzSaN0b9wUmsPoRS9b61A23Q=",
        version = "v0.27.0",
    )
    go_repository(
        name = "org_golang_x_text",
        build_file_proto_mode = "disable_global",
        importpath = "golang.org/x/text",
        sum = "h1:zyQAAkrwaneQ066sspRyJaG9VNi/YJ1NfzcGB3hZ/qo=",
        version = "v0.21.0",
    )
    go_repository(
        name = "org_golang_x_tools",
        build_file_proto_mode = "disable_global",
        importpath = "golang.org/x/tools",
        sum = "h1:vU5i/LfpvrRCpgM/VPfJLg5KjxD3E+hfT1SH+d9zLwg=",
        version = "v0.21.1-0.20240508182429-e35e4ccd0d2d",
    )
    go_repository(
        name = "org_golang_x_xerrors",
        build_file_proto_mode = "disable_global",
        importpath = "golang.org/x/xerrors",
        sum = "h1:go1bK/D/BFZV2I8cIQd1NKEZ+0owSTG1fDTci4IqFcE=",
        version = "v0.0.0-20200804184101-5ec99f83aff1",
    )
    go_repository(
        name = "org_uber_go_atomic",
        build_file_proto_mode = "disable_global",
        importpath = "go.uber.org/atomic",
        sum = "h1:ADUqmZGgLDDfbSL9ZmPxKTybcoEYHgpYfELNoN+7hsw=",
        version = "v1.7.0",
    )
    go_repository(
        name = "org_uber_go_goleak",
        build_file_proto_mode = "disable_global",
        importpath = "go.uber.org/goleak",
        sum = "h1:z+mqJhf6ss6BSfSM671tgKyZBFPTTJM+HLxnhPC3wu0=",
        version = "v1.1.10",
    )
    go_repository(
        name = "org_uber_go_multierr",
        build_file_proto_mode = "disable_global",
        importpath = "go.uber.org/multierr",
        sum = "h1:7fIwc/ZtS0q++VgcfqFDxSBZVv/Xo49/SYnDFupUwlI=",
        version = "v1.9.0",
    )
    go_repository(
        name = "org_uber_go_zap",
        build_file_proto_mode = "disable_global",
        importpath = "go.uber.org/zap",
        sum = "h1:CSUJ2mjFszzEWt4CdKISEuChVIXGBn3lAPwkRGyVrc4=",
        version = "v1.18.1",
    )
    go_repository(
        name = "tools_gotest_v3",
        build_file_proto_mode = "disable_global",
        importpath = "gotest.tools/v3",
        sum = "h1:MfDY1b1/0xN1CyMlQDac0ziEy9zJQd9CXBRRDHw2jJo=",
        version = "v3.3.0",
    )
