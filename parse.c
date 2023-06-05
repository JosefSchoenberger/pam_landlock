#define _GNU_SOURCE

#include <errno.h>
#include <grp.h>
#include <linux/landlock.h>
#include <pwd.h>
#include <security/pam_ext.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <syslog.h>

#include "prelude.h"
#include "landlock.h"
#include "vec.h"
#include "parse.h"

extern pam_handle_t *pamhandle;


static inline char* min(char* a, char* b) {
	return a < b ? a : b;
}

INTERNAL char* read_file(const char* path) {
	struct stat s;
	int result = stat(path, &s);
	if (result < 0) {
		log_err("Could not stat config file %s: %s", path, strerror(errno));
		return NULL;
	}

	if (s.st_mode & S_IWOTH) {
		pam_syslog(pamhandle, LOG_WARNING, "Config file %s is other-writable!", path);
	}

	FILE* file = fopen(path, "r");
	if (!file) {
		log_err("Could not open config file %s: %s", path, strerror(errno));
		return NULL;
	}

	char *buffer = malloc(s.st_size + 1);
	if (!buffer) {
		log_err("Could not allocate %zu bytes: %s", s.st_size + 1, strerror(errno));
		goto cleanup_file;
	}

	ssize_t nbytes = fread(buffer, 1, s.st_size, file);
	if (nbytes < 0) {
		log_err("Could not read config file: %s", strerror(errno));
		goto cleanup_free;
	}

	if (nbytes < s.st_size) {
		// What? EOF occured before all bytes were read. Race condition?
		pam_syslog(pamhandle, LOG_WARNING, "EOF occured before all bytes were read from config file %s. Race condition?", path);
		char* nbuf = realloc(buffer, nbytes + 1);
		if (!nbuf) {
			log_err("Could not reallocate to %zu bytes: %s", nbytes + 1, strerror(errno));
			goto cleanup_free;
		}
		buffer = nbuf;
	}

	buffer[nbytes] = '\0';

	fclose(file);
	return buffer;

cleanup_free:
	free(buffer);
cleanup_file:
	fclose(file);
	return NULL;
}

static uint64_t parse_allowed_access(const char* string, const char* path, unsigned line_no) {
	uint64_t allowed_access = 0;
	for (unsigned i = 0; string[i]; i++) {
		switch (string[i]) {
			case 'F':
				if (string[i + 1] != '(' || (strncmp(string + i + 1, "(*)", 3) == 0 && (i += 3))) {
					allowed_access |= LANDLOCK_ACCESS_FS_READ_FILE      \
									  | LANDLOCK_ACCESS_FS_WRITE_FILE   \
									  | LANDLOCK_ACCESS_FS_EXECUTE      \
									  | LANDLOCK_ACCESS_FS_TRUNCATE     \
									  | LANDLOCK_ACCESS_FS_REMOVE_FILE;
					break;
				}
				i+=2;
				for (; string[i] && string[i] != ')'; i++) {
					switch (string[i]) {
						case 'r': allowed_access |= LANDLOCK_ACCESS_FS_READ_FILE;   break; // *r*read
						case 'w': allowed_access |= LANDLOCK_ACCESS_FS_WRITE_FILE;  break; // *w*rite
						case 'x': allowed_access |= LANDLOCK_ACCESS_FS_EXECUTE;     break; // e*x*ecute
						case 't': allowed_access |= LANDLOCK_ACCESS_FS_TRUNCATE;    break; // *t*runcate
						case 'u': allowed_access |= LANDLOCK_ACCESS_FS_REMOVE_FILE; break; // *u*nlink
						case '-':
						case ',': break;
						default: pam_syslog(pamhandle, LOG_WARNING, "%s:%u: unknown file permission '%c', ignoring...", path, line_no, string[i]);
					}
				}
				if (string[i] == '\0') {
					pam_syslog(pamhandle, LOG_WARNING, "%s:%u: missing closing parenthesis for file permission", path, line_no);
					return allowed_access;
				}
				break;
			case 'D':
				if (string[i + 1] != '(' || (strncmp(string + i + 1, "(*)", 3) == 0 && (i += 3))) {
					allowed_access |= LANDLOCK_ACCESS_FS_READ_DIR      \
									  | LANDLOCK_ACCESS_FS_REFER       \
									  | LANDLOCK_ACCESS_FS_REMOVE_DIR  \
									  | LANDLOCK_ACCESS_FS_MAKE_CHAR   \
									  | LANDLOCK_ACCESS_FS_MAKE_DIR    \
									  | LANDLOCK_ACCESS_FS_MAKE_REG    \
									  | LANDLOCK_ACCESS_FS_MAKE_SOCK   \
									  | LANDLOCK_ACCESS_FS_MAKE_FIFO   \
									  | LANDLOCK_ACCESS_FS_MAKE_BLOCK  \
									  | LANDLOCK_ACCESS_FS_MAKE_SYM;
					break;
				}
				i+=2;
				for (; string[i] && string[i] != ')'; i++) {
					switch (string[i]) {
						case 'r': allowed_access |= LANDLOCK_ACCESS_FS_READ_DIR;   break; // *r*read
						case 'C':                                                         // *c*reate
							if (string[i + 1] != '(' || (strncmp(string + i + 1, "(*)", 3) == 0 && (i += 3))) {
								allowed_access |= LANDLOCK_ACCESS_FS_MAKE_CHAR    \
												  | LANDLOCK_ACCESS_FS_MAKE_DIR   \
												  | LANDLOCK_ACCESS_FS_MAKE_REG   \
												  | LANDLOCK_ACCESS_FS_MAKE_SOCK  \
												  | LANDLOCK_ACCESS_FS_MAKE_FIFO  \
												  | LANDLOCK_ACCESS_FS_MAKE_BLOCK \
												  | LANDLOCK_ACCESS_FS_MAKE_SYM;
								break;
							}
							i+=2;
							for (; string[i] && string[i] != ')'; i++) {
								switch (string[i]) {
									case 'c': allowed_access |= LANDLOCK_ACCESS_FS_MAKE_CHAR;  break;
									case 'd': allowed_access |= LANDLOCK_ACCESS_FS_MAKE_DIR;   break;
									case '-':
									case 'r': allowed_access |= LANDLOCK_ACCESS_FS_MAKE_REG;   break;
									case 's': allowed_access |= LANDLOCK_ACCESS_FS_MAKE_SOCK;  break;
									case 'f': allowed_access |= LANDLOCK_ACCESS_FS_MAKE_FIFO;  break;
									case 'b': allowed_access |= LANDLOCK_ACCESS_FS_MAKE_BLOCK; break;
									case 'l': allowed_access |= LANDLOCK_ACCESS_FS_MAKE_SYM;   break;
									case ',': break;
									default: pam_syslog(pamhandle, LOG_WARNING, "%s:%u: unknown file type '%c', ignoring...", path, line_no, string[i]);
								}
							}
							if (string[i] == '\0') {
								pam_syslog(pamhandle, LOG_WARNING, "%s:%u: missing closing parenthesis for rights specification", path, line_no);
								return allowed_access;
							}
							break;
						case 'u': allowed_access |= LANDLOCK_ACCESS_FS_REMOVE_DIR; break; // *u*nlink
						case 'm': allowed_access |= LANDLOCK_ACCESS_FS_REFER;      break; // *m*ove
						case '-':
						case ',': break;
						default: pam_syslog(pamhandle, LOG_WARNING, "%s:%u: unknown file permission '%c', ignoring...", path, line_no, string[i]);
					}
				}
				if (string[i] == '\0') {
					pam_syslog(pamhandle, LOG_WARNING, "%s:%u: missing closing parenthesis for file permission", path, line_no);
					return allowed_access;
				}
				break;
			case 'r': allowed_access |= LANDLOCK_ACCESS_FS_READ_FILE   \
									  | LANDLOCK_ACCESS_FS_EXECUTE     \
									  | LANDLOCK_ACCESS_FS_READ_DIR;
				break;
			case 'w': allowed_access |= LANDLOCK_ACCESS_FS_WRITE_FILE  \
									  | LANDLOCK_ACCESS_FS_REMOVE_FILE \
									  | LANDLOCK_ACCESS_FS_REMOVE_DIR  \
									  | LANDLOCK_ACCESS_FS_MAKE_CHAR   \
									  | LANDLOCK_ACCESS_FS_MAKE_DIR    \
									  | LANDLOCK_ACCESS_FS_MAKE_REG    \
									  | LANDLOCK_ACCESS_FS_MAKE_SOCK   \
									  | LANDLOCK_ACCESS_FS_MAKE_FIFO   \
									  | LANDLOCK_ACCESS_FS_MAKE_BLOCK  \
									  | LANDLOCK_ACCESS_FS_MAKE_SYM;
				break;
			case '*': allowed_access |= LANDLOCK_ACCESS_FS_READ_FILE   \
									  | LANDLOCK_ACCESS_FS_WRITE_FILE  \
									  | LANDLOCK_ACCESS_FS_EXECUTE     \
									  | LANDLOCK_ACCESS_FS_READ_DIR    \
									  | LANDLOCK_ACCESS_FS_REMOVE_FILE \
									  | LANDLOCK_ACCESS_FS_REMOVE_DIR  \
									  | LANDLOCK_ACCESS_FS_MAKE_CHAR   \
									  | LANDLOCK_ACCESS_FS_MAKE_DIR    \
									  | LANDLOCK_ACCESS_FS_MAKE_REG    \
									  | LANDLOCK_ACCESS_FS_MAKE_SOCK   \
									  | LANDLOCK_ACCESS_FS_MAKE_FIFO   \
									  | LANDLOCK_ACCESS_FS_MAKE_BLOCK  \
									  | LANDLOCK_ACCESS_FS_MAKE_SYM    \
									  | LANDLOCK_ACCESS_FS_TRUNCATE    \
									  | LANDLOCK_ACCESS_FS_REFER;
				break;
			case ',': break;
			default: pam_syslog(pamhandle, LOG_WARNING, "%s:%u: unknown access right '%c', ignoring...", path, line_no, string[i]);
		}
	}
	return allowed_access;
}

static char* find_and_unescape_path(char* path, const char* endchars, bool may_end_with_nullbyte, const char* filename, unsigned line_no) {
	char *in = path, *out = path;
	if (in[0] == '"') {
		endchars = "\"";
		in ++;
	}

	char *end = strchrnul(in, *endchars);
	for (unsigned i = 1; endchars[i]; i++)
		end = min(end, strchrnul(in, endchars[i]));
	if (*end == '\0' && !may_end_with_nullbyte) {
		pam_syslog(pamhandle, LOG_WARNING, "%s:%u: Could not find any terminating character (any in \"%s\") in path",
				filename, line_no, *endchars == '"' ? "\\\"" : endchars);
		return NULL;
	}
	*end = '\0';
	for (;;) {
		char *backspace_or_end = strchrnul(in, '\\');
		memmove(out, in, backspace_or_end - in);
		out += backspace_or_end - in;
		in = backspace_or_end;

		if (!backspace_or_end[0]) {
			*out = '\0';
			return end + 1;
		}

		switch(backspace_or_end[1]) {
			case '\\': *out++ = '\\'; in += 2; break;
			case 'a':  *out++ = '\a'; in += 2; break;
			case 'b':  *out++ = '\b'; in += 2; break;
			case 'f':  *out++ = '\f'; in += 2; break;
			case 'n':  *out++ = '\n'; in += 2; break;
			case 'r':  *out++ = '\r'; in += 2; break;
			case 't':  *out++ = '\t'; in += 2; break;
			case 'v':  *out++ = '\v'; in += 2; break;
			case '0':
			case 'o': {
					unsigned char c = 0;
					in += 2;
					for (int i = 0; i < 3 && *in >= '0' && *in <= '7'; i++)
						c = c * 8 + (*in++ - '0');
					*out ++ = (char) c;
				};
				break;
		}
	}
}

static char* ltrim(char* string) {
	string += strspn(string, " \t");
	return string;
}

static char* rtrim(char* string) {
	for(char* c = string + strlen(string) - 1; c >= string && (*c == ' ' || *c == '\t'); c--)
		*c = '\0';
	return string;
}

static inline char* trim(char* string) {
	return rtrim(ltrim(string));
}

enum id_type {
	GROUP,
	USER,
};

static int parse_ids(char *list, struct ids* out_list_positive, struct ids* out_list_negative, enum id_type type) {
	struct intvec p = intvec_new(0);
	if (p.error) return -1;
	struct intvec n = intvec_new(0);
	if (p.error) return -1;

	char* saveptr = NULL;
	for (char* id_string = strtok_r(list, ",", &saveptr); id_string; id_string = strtok_r(NULL, ",", &saveptr)) {
		id_string = trim(id_string);

		bool negative = *id_string == '!';
		if (negative) {
			id_string = ltrim(id_string + 1);
		}

		unsigned id;
		if (*id_string >= '0' && *id_string <= '9') {
			char c = type == USER ? 'u' : 'g';
			char* endptr;
			long long result = strtoll(id_string, &endptr, 0);
			if (*endptr) {
				pam_syslog(pamhandle, LOG_WARNING, "%cid \"%s\" is not a valid number", c, id_string);
				continue;
			}
			if (result < 0 || result > (1ll << sizeof(gid_t)*8) - 1) {
				pam_syslog(pamhandle, LOG_WARNING, "%cid %s is not a valid %cid (%lld)", c, id_string, c, result);
				continue;
			}
			id = result;
		} else {
			if (type == USER) {
				errno = 0;
				struct passwd *u = getpwnam(id_string);
				if (!u) {
					pam_syslog(pamhandle, LOG_WARNING, "user id for user \"%s\" could not be determined: %s", id_string, errno ? strerror(errno) : "No such user");
					continue;
				}
				id = u->pw_uid;
			} else {
				errno = 0;
				struct group *g = getgrnam(id_string);
				if (!g) {
					pam_syslog(pamhandle, LOG_WARNING, "group id for group \"%s\" could not be determined: %s", id_string, errno ? strerror(errno) : "No such group");
					continue;
				}
				id = g->gr_gid;
			}
		}
		if(intvec_append(negative ? &n : &p, id))
			goto cleanup;
	}
	if (intvec_resize_to_fit(&p) || intvec_resize_to_fit(&n))
		goto cleanup;

	out_list_positive->id = p.ptr;
	out_list_positive->cnt  = p.len;
	out_list_negative->id = n.ptr;
	out_list_negative->cnt  = n.len;
	return 0;

cleanup:
	intvec_cleanup(&p);
	intvec_cleanup(&n);
	return -1;
}

static int parse_commaseparated_paths(char* paths, struct strings *strings, const char* filename, unsigned line_no) {
	struct ptrvec v = ptrvec_new(0);
	char* end = paths + strlen(paths);
	if (strchr(paths, '/')) {
		log_err("%s:%u: excludes may not contain any slashes. Ignoring all excludes...", filename, line_no);
		goto cleanup;
	}
	while(paths < end) {
		paths += strspn(paths, " \t,");
		if (!*paths)
			break;
		char* rest = find_and_unescape_path(paths, ",", true, filename, line_no);
		if (!rest)
			goto cleanup;
		if (ptrvec_append(&v, paths))
			goto cleanup;
		paths = rest;
	}

	if (ptrvec_resize_to_fit(&v))
		goto cleanup;

	strings->string = (char**) v.ptr;
	strings->cnt = v.len;

	return 0;

cleanup:
	ptrvec_cleanup(&v);
	return -1;
}

static char* parse_rule(struct landlock_rule* rule, char* config_line, const char* filename, unsigned line_no) {
	char* end = config_line + strlen(config_line);

	rule->path = config_line;
	config_line = find_and_unescape_path(config_line, " \t", false, filename, line_no);
	if (!config_line)
		goto cleanup;

	config_line += strspn(config_line, " \t");
	char* next_whitespace = min(strchrnul(config_line, ' '), strchrnul(config_line, '\t'));
	bool options = false;
	if (*next_whitespace) {
		*next_whitespace = '\0';
		options = true;
	}

	if(config_line == next_whitespace) {
		pam_syslog(pamhandle, LOG_WARNING, "%s:%u: Rule has no access rights specification. Ignoring rule...", filename, line_no);
		goto cleanup;
	}

	rule->allowed_access = parse_allowed_access(config_line, filename, line_no);

	// Options are optional...
	if (!options)
		return end;

	config_line = next_whitespace + 1;
	config_line += strspn(config_line, " \t");
	if (*config_line == '#')
		return end;

	char* saveptr = NULL;
	for (char *key = strtok_r(config_line, ";", &saveptr); key; key = strtok_r(NULL, ";", &saveptr)) {
		char * comment_start = strchr(key, '#');
		if (comment_start)
			*comment_start = '\0';
		char* val = strchr(key, '=');
		if (val) {
			*val = '\0';
			val ++;
		}
		//pam_syslog(pamhandle, LOG_DEBUG, "%s:%u: %s => %s", filename, line_no, key, val);

		if (!val) {
			log_err("%s:%u: key \"%s\" requires arguments", filename, line_no, key);
			if (comment_start)
				break;
			else
				continue;
		}

		key += strspn(config_line, " \t");

		if (strcmp(key, "gid") == 0) {
			if(parse_ids(val, &rule->gids, &rule->not_gids, GROUP))
				goto cleanup;
		} else if (strcmp(key, "uid") == 0) {
			if(parse_ids(val, &rule->uids, &rule->not_uids, USER))
				goto cleanup;
		} else if (strcmp(key, "exclude") == 0) {
			if(parse_commaseparated_paths(val, &rule->exclude, filename, line_no))
				goto cleanup;
		} else {
			log_err("%s:%u: unknown key \"%s\"", filename, line_no, key);
		}

		if (comment_start)
			break;
	}

	return end;

cleanup:
	if(rule->uids.id) free(rule->uids.id);
	if(rule->gids.id) free(rule->gids.id);
	if(rule->not_uids.id) free(rule->not_uids.id);
	if(rule->not_gids.id) free(rule->not_gids.id);
	rule->path = NULL;
	return end; // continue with next line...
}

INTERNAL struct landlock_rule** parse_file(char* filedata, const char* filename) {
	struct ptrvec rules = ptrvec_new(8);
	if (rules.error) {
		return NULL;
	}
	const char* end = filedata + strlen(filedata);
	unsigned line_no = 0;
	*strchrnul(filedata, '\n') = '\0';
	for (char* line = filedata; line < end; *strchrnul(++line, '\n') = '\0') {
		line_no++;

		// skip if empty or comment
		size_t whitespaces = strspn(line, " \t");
		line += whitespaces;
		if (!*line || *line == '#') {
			line += strlen(line);
			continue;
		}

		struct landlock_rule* rule = calloc(1, sizeof(*rule));
		if (!rule) {
			log_err("Could not allocate %zu bytes: %s", sizeof(*rule), strerror(errno));
			goto cleanup;
		}

		char* endptr = parse_rule(rule, line, filename, line_no);
		if (!endptr) {
			free(rule);
			goto cleanup;
		}
		line = endptr;

		// Could not parse this line, but may continue with next the next one
		if (!rule->path) {
			free(rule);
			continue;
		}

		if (ptrvec_append(&rules, rule)) {
			free(rule);
			goto cleanup;
		}
	}

	if (ptrvec_resize_to_fit(&rules)) {
		goto cleanup;
	}

	return (struct landlock_rule**) rules.ptr;

cleanup:
	ptrvec_cleanup(&rules);
	return NULL;
}

static void cleanup_rule(struct landlock_rule* rule) {
	if (!rule)
		return;
	if(rule->gids.id) free(rule->gids.id);
	if(rule->not_gids.id) free(rule->not_gids.id);
	if(rule->uids.id) free(rule->uids.id);
	if(rule->not_uids.id) free(rule->not_uids.id);
	if(rule->exclude.string) free(rule->exclude.string);
	free(rule);
}

INTERNAL void cleanup_ruleset(struct landlock_rule** ruleset) {
	if (!ruleset)
		return;
	for (struct landlock_rule** r = ruleset; *r; r++)
		cleanup_rule(*r);
	free(ruleset);

}

INTERNAL void debug_ruleset(struct landlock_rule** rules) {
	for (struct landlock_rule** r = rules; *r; r++) {
		struct landlock_rule *x = *r;
		printf("0x%04lx path=\"%s\"\n", x->allowed_access, x->path);
		if (x->uids.cnt) {
			printf("  | user = [");
			for(size_t i = 0; i < x->uids.cnt - 1; i++) {
				printf("%d, ", x->uids.id[i]);
			}
			printf("%d]\n", x->uids.id[x->uids.cnt - 1]);
		}
		if (x->not_uids.cnt) {
			printf("  | !user = [");
			for(size_t i = 0; i < x->not_uids.cnt - 1; i++) {
				printf("%d, ", x->not_uids.id[i]);
			}
			printf("%d]\n", x->not_uids.id[x->not_uids.cnt - 1]);
		}
		if (x->gids.cnt) {
			printf("  | groups = [");
			for(size_t i = 0; i < x->gids.cnt - 1; i++) {
				printf("%d, ", x->gids.id[i]);
			}
			printf("%d]\n", x->gids.id[x->gids.cnt - 1]);
		}
		if (x->not_gids.cnt) {
			printf("  | !groups = [");
			for(size_t i = 0; i < x->not_gids.cnt - 1; i++) {
				printf("%d, ", x->not_gids.id[i]);
			}
			printf("%d]\n", x->not_gids.id[x->not_gids.cnt - 1]);
		}
		if (x->exclude.cnt) {
			printf("  | excludes = [");
			for(size_t i = 0; i < x->exclude.cnt - 1; i++) {
				printf("\"%s\", ", x->exclude.string[i]);
			}
			printf("\"%s\"]\n", x->exclude.string[x->exclude.cnt - 1]);
		}
	}
}

#if 0
// useful for testing the parser
int main(int argc, char** argv) {
	if (argc != 2) {
		fprintf(stderr, "usage: %s <file>\n", argv[0] ?: "<argv[0] missing>");
		return EXIT_FAILURE;
	}

	char* buf = read_file(argv[1]);
	if (!buf)
		return PAM_SESSION_ERR;
	struct landlock_rule** rules = parse_file(buf, argv[1]);
	if (!rules) {
		free(buf);
		return PAM_SESSION_ERR;
	}

	for (struct landlock_rule** r = rules; *r; r++) {
		struct landlock_rule *x = *r;
		printf("0x%04lx path=\"%s\"\n", x->allowed_access, x->path);
		if (x->uids.cnt) {
			printf("  | user = [");
			for(size_t i = 0; i < x->uids.cnt - 1; i++) {
				printf("%d, ", x->uids.id[i]);
			}
			printf("%d]\n", x->uids.id[x->uids.cnt - 1]);
		}
		if (x->not_uids.cnt) {
			printf("  | !user = [");
			for(size_t i = 0; i < x->not_uids.cnt - 1; i++) {
				printf("%d, ", x->not_uids.id[i]);
			}
			printf("%d]\n", x->not_uids.id[x->not_uids.cnt - 1]);
		}
		if (x->gids.cnt) {
			printf("  | groups = [");
			for(size_t i = 0; i < x->gids.cnt - 1; i++) {
				printf("%d, ", x->gids.id[i]);
			}
			printf("%d]\n", x->gids.id[x->gids.cnt - 1]);
		}
		if (x->not_gids.cnt) {
			printf("  | !groups = [");
			for(size_t i = 0; i < x->not_gids.cnt - 1; i++) {
				printf("%d, ", x->not_gids.id[i]);
			}
			printf("%d]\n", x->not_gids.id[x->not_gids.cnt - 1]);
		}
		if (x->exclude.cnt) {
			printf("  | excludes = [");
			for(size_t i = 0; i < x->exclude.cnt - 1; i++) {
				printf("\"%s\", ", x->exclude.string[i]);
			}
			printf("\"%s\"]\n", x->exclude.string[x->exclude.cnt - 1]);
		}
	}

	cleanup_ruleset(rules);
	free(buf);

	log_err("a");
}
#endif
