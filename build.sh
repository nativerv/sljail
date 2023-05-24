#!/bin/sh

for file in $(find ./seccomp -type f -iname '*.c'); do
  temp="$(mktemp)"
  gcc -Wall -Wextra -lseccomp -o "${temp}" "${file}" &&
    "${temp}" > "${file%.c}"
done

gcc -Wall -Wextra -o './test/tiocsti_ioctl_escape' './test/tiocsti_ioctl_escape.c'
