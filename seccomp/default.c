#define _GNU_SOURCE
#include <stdio.h>
#include <seccomp.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>

  /**** Note from nrv:
   * I took the following filter list from the Flatpak source code, at the following address:
   * https://github.com/flatpak/flatpak/blob/4c6136ab2146234bff37925b218026de846d584e/common/flatpak-run.c#L1780
   * It had the below note in it. So here it is.
   */

  /**** BEGIN NOTE ON CODE SHARING
   *
   * There are today a number of different Linux container
   * implementations.  That will likely continue for long into the
   * future.  But we can still try to share code, and it's important
   * to do so because it affects what library and application writers
   * can do, and we should support code portability between different
   * container tools.
   *
   * This syscall blocklist is copied from linux-user-chroot, which was in turn
   * clearly influenced by the Sandstorm.io blocklist.
   *
   * If you make any changes here, I suggest sending the changes along
   * to other sandbox maintainers.  Using the libseccomp list is also
   * an appropriate venue:
   * https://groups.google.com/forum/#!forum/libseccomp
   *
   * A non-exhaustive list of links to container tooling that might
   * want to share this blocklist:
   *
   *  https://github.com/sandstorm-io/sandstorm
   *    in src/sandstorm/supervisor.c++
   *  https://github.com/flatpak/flatpak.git
   *    in common/flatpak-run.c
   *  https://git.gnome.org/browse/linux-user-chroot
   *    in src/setup-seccomp.c
   *
   * Other useful resources:
   * https://github.com/systemd/systemd/blob/HEAD/src/shared/seccomp-util.c
   * https://github.com/moby/moby/blob/HEAD/profiles/seccomp/default.json
   *
   **** END NOTE ON CODE SHARING
   */

int main() {
    scmp_filter_ctx ctx = NULL;

    // Allow all by default
    ctx = seccomp_init(SCMP_ACT_ALLOW);

    // The blacklist
    /* Block dmesg */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (syslog), 0);
    /* Useless old syscall */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (uselib), 0);
    /* Don't allow disabling accounting */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (acct), 0);
    /* Don't allow reading current quota use */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (quotactl), 0);

    /* Don't allow access to the kernel keyring */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (add_key), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (keyctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (request_key), 0);

    /* Scary VM/NUMA ops */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (move_pages), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (mbind), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (get_mempolicy), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (set_mempolicy), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (migrate_pages), 0);

    /* Don't allow subnamespace setups: */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (unshare), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (setns), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (mount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (umount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (umount2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (pivot_root), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (chroot), 0);
#if defined(__s390__) || defined(__s390x__) || defined(__CRIS__)
    /* Architectures with CONFIG_CLONE_BACKWARDS2: the child stack
     * and flags arguments are reversed so the flags come second */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (clone), 1, &SCMP_A1 (SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER));
#else
    /* Normally the flags come first */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (clone), 1, &SCMP_A0 (SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER));
#endif

    /* Don't allow faking input to the controlling tty (CVE-2017-5226) */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (ioctl), 1, &SCMP_A1 (SCMP_CMP_MASKED_EQ, 0xFFFFFFFFu, (int) TIOCSTI));
    /* In the unlikely event that the controlling tty is a Linux virtual
     * console (/dev/tty2 or similar), copy/paste operations have an effect
     * similar to TIOCSTI (CVE-2023-28100) */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS (ioctl), 1, &SCMP_A1 (SCMP_CMP_MASKED_EQ, 0xFFFFFFFFu, (int) TIOCLINUX));

    /* seccomp can't look into clone3()'s struct clone_args to check whether
     * the flags are OK, so we have no choice but to block clone3().
     * Return ENOSYS so user-space will fall back to clone().
     * (GHSA-67h7-w3jq-vh4q; see also https://github.com/moby/moby/commit/9f6b562d) */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS (clone3), ENOSYS);

    /* New mount manipulation APIs can also change our VFS. There's no
     * legitimate reason to do these in the sandbox, so block all of them
     * rather than thinking about which ones might be dangerous.
     * (GHSA-67h7-w3jq-vh4q) */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS (open_tree), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS (move_mount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS (fsopen), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS (fsconfig), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS (fsmount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS (fspick), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS (mount_setattr), 0);

    // Export the seccomp filter to a BPF program
    if (seccomp_export_bpf(ctx, open("/dev/stdout", O_WRONLY)) != 0) {
        perror("seccomp_export_bpf");
        return 1;
    }

    seccomp_release(ctx);
    return 0;
}
