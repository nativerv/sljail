#include <stdio.h>
#include <seccomp.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    scmp_filter_ctx ctx = NULL;

    ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    // Allow read, write, exit, and fstat system calls
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);

    // Export the seccomp filter to a BPF program
    if (seccomp_export_bpf(ctx, open("/dev/stdout", O_WRONLY)) != 0) {
        perror("seccomp_export_bpf");
        return 1;
    }

    seccomp_release(ctx);
    return 0;
}
