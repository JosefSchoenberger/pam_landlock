#pragma once
#include <stdbool.h>
#include <sys/types.h>


#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#  define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_FS_REFER
#  define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif

struct landlock_rule;
int restrict_to_ruleset(struct landlock_rule** ruleset, bool allow_privs, uid_t user);
