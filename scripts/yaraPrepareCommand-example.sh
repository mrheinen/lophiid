#!/bin/sh

# This is an example script that can be used to unpack the malware before the
# yara scan runs. Unpacked files need to have an .unpacked extension.
#
# The script receives the file as the first argument.
#
## This script makes use of https://github.com/cloudflare/sandbox to sandbox the UPX command.

MALWARE_FILE=$1

LD_PRELOAD=/disk/niels/coding/sandbox/libsandbox.so SECCOMP_SYSCALL_ALLOW="access:arch_prctl:brk:chmod:chown:close:exit_group:fstat:futex:getrandom:ioctl:lseek:mmap:mprotect:munmap:newfstatat:openat:pread64:prlimit64:read:rename:rseq:rt_sigaction:set_robust_list:set_tid_address:sigaltstack:unlink:utimensat:write:clock_gettime" upx -d ${MALWARE_FILE} -o ${MALWARE_FILE}.unpacked
