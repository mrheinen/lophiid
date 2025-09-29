This is a simple test utility to test the AI shell emulation logic.


Example run:

```shell
$ bazel build //cmd/shell:shell
INFO: Analyzed target //cmd/shell:shell (0 packages loaded, 0 targets configured).
INFO: Found 1 target...
Target //cmd/shell:shell up-to-date:
  bazel-bin/cmd/shell/shell_/shell
INFO: Elapsed time: 0.285s, Critical Path: 0.00s
INFO: 1 process: 1 internal.
INFO: Build completed successfully, 1 total action

$ bazel-bin/cmd/shell/shell_/shell -c backend-config.yaml
ls
Running command: ls
time=2025-09-29T12:32:41.442Z level=DEBUG msg="Running query" query="FROM session_execution_context WHERE (session_id = $1)  ORDER BY created_at DESC OFFSET 0 LIMIT 20" values=1
time=2025-09-29T12:32:41.446Z level=DEBUG msg="query took" elapsed=3.606688ms
time=2025-09-29T12:32:41.446Z level=DEBUG msg="setting response schema"
aap Desktop Documents Downloads Music Pictures Public Templates Videos config.json example.txt free,txt

USER=devuser
CWD=/home/devuser
HOSTNAME=webserver
```
