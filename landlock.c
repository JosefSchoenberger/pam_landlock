#define _GNU_SOURCE
#include <stdbool.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "prelude.h"
#include "landlock.h"
#include "parse.h"

extern pam_handle_t *pamhandle;

static inline int landlock_add_rule(int landlock_fd, enum landlock_rule_type rule_type, const void *rule_attr, uint32_t flags) {
	return syscall(SYS_landlock_add_rule, landlock_fd, rule_type, rule_attr, flags);
}

static inline int landlock_restrict_self(int ruleset_fd, uint32_t flags) {
	return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}

static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, uint32_t flags) {
	return syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

static uint64_t fs_accesses_mask;

static const uint64_t fs_file_accesses = LANDLOCK_ACCESS_FS_EXECUTE \
										 | LANDLOCK_ACCESS_FS_WRITE_FILE \
										 | LANDLOCK_ACCESS_FS_READ_FILE;

// Either maybe_path or maybe_parent must not be NULL.
static int is_dir(int path_fd, const char* path) {
	struct stat s;
	int r = fstatat(path_fd, "", &s, AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH);
	if (r < 0) {
		log_err("Could not stat \"%s\": %s", path, strerror(errno));
		return -1;
	}
	return !!S_ISDIR(s.st_mode);
}

static int set_allowed_access(int landlock_fd, int path_at, const char* dirname, uint64_t allowed_access) {
	int dir_fd = openat(path_at, dirname, O_PATH | O_CLOEXEC | O_NOFOLLOW);
	if (dir_fd < 0) {
		pam_syslog(pamhandle, LOG_WARNING, "Could not open path \"%s\" with O_PATH: %s. This path may now not be accessible at all.", dirname, strerror(errno));
		return -1;
	}

	allowed_access &= ~fs_accesses_mask;
	if (!is_dir(dir_fd, dirname))
		allowed_access &= fs_file_accesses;

	struct landlock_path_beneath_attr pba = {
		.allowed_access = allowed_access,
		.parent_fd = dir_fd,
	};

	if (landlock_add_rule(landlock_fd, LANDLOCK_RULE_PATH_BENEATH, &pba, 0)) {
		log_err("Could not set access rights for path \"%s\": %s", dirname, strerror(errno));
		close(dir_fd);
		return -1;
	}
	close(dir_fd);
	return 0;
}

static int allow_all_except(int landlock_fd, const char* dirname, uint64_t allowed_access, const char* exceptions[], size_t exception_count) {
	DIR* dir = opendir(dirname);
	if (!dir) {
		log_err("Could not open directory \"%s\": %s", dirname, strerror(errno));
		return -1;
	}

	for (;;) {
cont:
		errno = 0;
		struct dirent* d = readdir(dir);
		if (!d) {
			if (errno) {
				log_err("Could not read entry in directory \"%s\": %s", dirname, strerror(errno));
			}
			break;
		}

		uint64_t a = allowed_access;
		if (d->d_type != DT_DIR)
			a &= LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;

		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		for (size_t i = 0; i < exception_count; i++)
			if (!strcmp(d->d_name, exceptions[i]))
				goto cont;

		// Ignoring the error
		set_allowed_access(landlock_fd, dirfd(dir), d->d_name, a);
	}
	closedir(dir);
	return 0;
}

static const uint64_t supported_access = LANDLOCK_ACCESS_FS_EXECUTE \
										 | LANDLOCK_ACCESS_FS_WRITE_FILE \
										 | LANDLOCK_ACCESS_FS_READ_FILE \
										 | LANDLOCK_ACCESS_FS_READ_DIR \
										 | LANDLOCK_ACCESS_FS_REMOVE_DIR \
										 | LANDLOCK_ACCESS_FS_REMOVE_FILE \
										 | LANDLOCK_ACCESS_FS_MAKE_CHAR \
										 | LANDLOCK_ACCESS_FS_MAKE_DIR \
										 | LANDLOCK_ACCESS_FS_MAKE_REG \
										 | LANDLOCK_ACCESS_FS_MAKE_SOCK \
										 | LANDLOCK_ACCESS_FS_MAKE_FIFO \
										 | LANDLOCK_ACCESS_FS_MAKE_BLOCK \
										 | LANDLOCK_ACCESS_FS_MAKE_SYM \
										 | LANDLOCK_ACCESS_FS_TRUNCATE \
										 | LANDLOCK_ACCESS_FS_REFER;

static int update_landlock_version_mask() {
	uint64_t mask = ~supported_access;
	int abi_version = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi_version < 0) {
		if (errno == ENOSYS)
			log_err("Your system does not support landlock.");
		else if (errno == EOPNOTSUPP)
			log_err("Landlock is currently disabled on your system.");
		else
			log_err("Could not get ABI version of landlock: %s", strerror(errno));
		return -1;
	}

	switch (abi_version) {
		case 1: mask |= LANDLOCK_ACCESS_FS_REFER;
				  /* FALL-THROUGH */
		case 2: mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
				  /* FALL-THROUGH */
		case 3: break;
		default:
				pam_syslog(pamhandle, LOG_INFO, "The kernel offeres a newer ABI version (%d) than this version of pam_landlock supports (%d). Please consider updating me.", abi_version, 3);
	}
	fs_accesses_mask = mask;
	return 0;
}

// Returns 0 for false, 1 for true and -1 for error
static int check_user_predicates(struct landlock_rule* rule, struct passwd *pw) {
	for (size_t i = 0; i < rule->not_uids.cnt; i++)
		if (rule->not_uids.id[i] == pw->pw_uid)
			return 0;
	for (size_t i = 0; i < rule->uids.cnt; i++)
		if (rule->uids.id[i] == pw->pw_uid)
			return 1;

	int group_buffer_size = 32;
	gid_t *group_buffer = malloc(sizeof(gid_t) * group_buffer_size);
	if (!group_buffer) {
		log_err("Could not allocate %zu bytes: %s", sizeof(gid_t) * group_buffer_size, strerror(errno));
		return -1;
	}

	int ngroups = group_buffer_size;
	int res = getgrouplist(pw->pw_name, pw->pw_gid, group_buffer, &ngroups);
	while (res < 0) {
		group_buffer = realloc(group_buffer, sizeof(gid_t) * ngroups);
		if (!group_buffer) {
			log_err("Could not reallocate %zu to %zu bytes: %s", sizeof(gid_t) * group_buffer_size, sizeof(gid_t) * ngroups, strerror(errno));
			free(group_buffer);
			return -1;
		}
		res = getgrouplist(pw->pw_name, pw->pw_gid, group_buffer, &ngroups);
	}

	for (size_t i = 0; i < rule->not_gids.cnt; i++)
		for (int j = 0; j < ngroups; j++)
			if (rule->not_gids.id[i] == group_buffer[j]) {
				free(group_buffer);
				return 0;
			}
	for (size_t i = 0; i < rule->gids.cnt; i++)
		for (int j = 0; j < ngroups; j++)
			if (rule->gids.id[i] == group_buffer[j]) {
				free(group_buffer);
				return 1;
			}

	free(group_buffer);

	return !rule->gids.cnt && (rule->not_gids.cnt || !rule->not_uids.cnt);
}

INTERNAL int restrict_to_ruleset(struct landlock_rule** ruleset, bool allow_privs, uid_t user) {
	int res = 0;
	struct passwd *pw = getpwuid(user);
	if (!pw) {
		log_err("User (UID %u) does not exist?", user);
		return -1;
	}

	res = update_landlock_version_mask();
	if (res)
		return res;

	struct landlock_ruleset_attr attr = {
		.handled_access_fs = supported_access & ~fs_accesses_mask,
	};
	int landlock_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	if (landlock_fd < 0) {
		log_err("Could not create landlock ruleset: %s", strerror(errno));
		return -1;
	}

	for(struct landlock_rule** rp = ruleset; *rp; rp++) {
		struct landlock_rule* r = *rp;
		int res = check_user_predicates(r, pw);
		if (res < 0)
			goto out;
		pam_syslog(pamhandle, LOG_DEBUG, "Rule for path %-10s -> user predicate: %d", r->path, res);
		if (res == 0)
			continue;

		if (!r->exclude.cnt) {
			//res =
			set_allowed_access(landlock_fd, AT_FDCWD, r->path, r->allowed_access);
		} else {
			//res =
			allow_all_except(landlock_fd, r->path, r->allowed_access, (const char**) r->exclude.string, r->exclude.cnt);
		}
		//if (res < 0)
		//	goto out;
		continue;
	}

	if (!allow_privs) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			log_err("prctl(...): Could not set PR_SET_NO_NEW_PRIVS: %s", strerror(errno));
			res = -1;
			goto out;
		}
	}

	if (landlock_restrict_self(landlock_fd, 0)) {
		log_err("Could not restrict process with landlock: %s%s", strerror(errno),
				(errno == EPERM && allow_privs) ? ". Consider removing the -p / --allow-privs flag." : "");
		res = -1;
		goto out;
	}

out:
	close(landlock_fd);
	return res;
}
