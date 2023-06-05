#pragma once
#include <stddef.h>
#include <stdint.h>

char* read_file(const char* path);

struct ids {
	unsigned *id;
	size_t cnt;
};

struct strings {
	char** string;
	size_t cnt;
};

struct landlock_rule {
	char *path;
	uint64_t allowed_access;
	struct ids gids;
	struct ids not_gids;
	struct ids uids;
	struct ids not_uids;
	struct strings exclude;
};

/**
 * Parses a config file.
 * The result has to be cleaned up using `cleanup_rule`, unless there was an error, in which case NULL is returned.
 * Keep in mind that the result will have pointers into `filedata`, so please ensure that the filedata has a long enough lifetime.
 *
 * Parameters:
 * - filedata: The config file data
 * - filename: The filename of the file (for error messages)
 * Returns:
 * - The parsed result. May be NULL on error.
 */
struct landlock_rule** parse_file(char* filedata, const char* filename);

/**
 * Cleans up the parsed results from `parse_file`.
 * `ruleset` may be NULL.
 */
void cleanup_ruleset(struct landlock_rule** ruleset);

void debug_ruleset(struct landlock_rule** rules);
