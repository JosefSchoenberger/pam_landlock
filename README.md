# pam\_landlock

a PAM module for limiting users' access to the filesystem

## Installation
Run as root:
```shell
make install
```
Then, append
```pam
session required pam_landlock.so --allow-privs
```
to **both** `/etc/pam.d/common-session` (for interactive sessions) and `/etc/pam.d/common-session-noninteractive` (for non-interactive sessions).

For testing purposes, I recommend using `optional` instead of `required` to avoid locking yourself out of your own system.

## Configuration
See the documentation in default.conf.
