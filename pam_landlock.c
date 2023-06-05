#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "prelude.h"
#include "parse.h"
#include "landlock.h"


INTERNAL pam_handle_t *pamhandle;

struct args {
	char* config_path;
	bool allow_privs;
	bool explicit_user;
	char* user;
#ifdef AS_EXECUTABLE
	char** command;
#endif
};

static int parse_args(struct args* a, int argc, char** argv) {
	for(;;) {
		static struct option long_options[] = {
#ifdef AS_EXECUTABLE
			{"version",     no_argument,       0, 'v'},
			{"help",        no_argument,       0, 'h'},
#endif
			{"configfile",  required_argument, 0, 'c'},
			{"allow-privs", no_argument,       0, 'p'},
			{"for-user",    required_argument, 0, 'u'},
			{0,0,0,0}
		};
		int choice = getopt_long( argc, argv, ":"
#ifdef AS_EXECUTABLE
				"hv"
#endif
				"c:pu:", long_options, NULL);

		if (choice == -1)
			break;

		switch(choice) {
#ifdef AS_EXECUTABLE
			case 'v':
				puts("pam_landlock 0.1\nBuilt on " __DATE__ ", " __TIME__);
				exit(EXIT_SUCCESS);
			case 'h':
				printf ("Usage: %s [options] [--] command\n\n"
						"Options:\n"
						"  -h --help              Print this help message and exit\n"
						"  -c --configfile=<path> Configuration file. Default is /etc/security/landlock.conf\n"
						"  -p --allow-privs       Allow subsequent command to execute setUID/setGID executables (know the risks!)\n"
						"  -u --for-user=<user>   Apply the rules as you would for user <user>. <user> be a name or numeric id\n"
						"  -v --version           Print the version and exit\n"
						, argv[0] ?: "pam_landlock");
				exit(EXIT_SUCCESS);
				break;
#endif
			case 'c':
				a->config_path = optarg;
				break;
			case 'p':
				a->allow_privs = true;
				break;
			case 'u':
				a->explicit_user = true;
				a->user = optarg;
				break;
			case ':':
				// FIXME how is a long option passed into the int optopt?
				log_err("Option %c requires an argument", optopt);
				exit(EXIT_FAILURE);
				break;
			case '?':
				// FIXME how is a long option passed into the int optopt?
				log_err("Unknown option %c", optopt);
				exit(EXIT_FAILURE);
				break;
			default:
				exit(EXIT_FAILURE);
		}
	}

	/* Deal with non-option arguments here */
	if (optind < argc) {
#ifndef AS_EXECUTABLE
		pam_syslog(pamhandle, LOG_WARNING, "Surplus arguments, ignored: %s", argv[optind]);
#else
		a->command = argv + optind;
	} else {
		log_err("Missing command");
		exit(EXIT_FAILURE);
#endif
	}

	if (!a->config_path)
		a->config_path = "/etc/security/landlock.conf";
	return 0;
}

static int parse_user(const char* name, uid_t *user) {
	if ((*name >= '0' && *name <= '9') || *name == '-') {
		char *endptr;
		long long r = strtoll(name, &endptr, 0);
		if(*endptr) {
			log_err("UID \"%s\" is not a valid integer", name);
			return -1;
		}
		if (r < 0 || r > 0xFFFFFFFF) {
			log_err("UID %lld is out of range", r);
			return -1;
		}
		*user = (uid_t) r;
	} else {
		errno = 0;
		struct passwd* pw = getpwnam(name);
		if (!pw) {
			log_err("Could not find user %s: %s", name, errno ? strerror(errno) : "No such user");
			return -1;
		}
		*user = pw->pw_uid;
	}
	return 0;
}

static int doit(struct args* a, uid_t user) {
	int r = -1;

	if (a->explicit_user) {
		r = parse_user(a->user, &user);
		if (r)
			return r;
	}

	char* configdata = read_file(a->config_path);
	if (!configdata)
		return -1;

	struct landlock_rule** rules = parse_file(configdata, a->config_path);
	if (!rules) {
		r = -1;
		goto out_free;
	}

	//debug_ruleset(rules);

	r = restrict_to_ruleset(rules, a->allow_privs, user);
	if (r)
		goto out_cleanup;

	r = 0;

out_cleanup:
	cleanup_ruleset(rules);
out_free:
	free(configdata);
	return r;
}

#if 1
#ifdef AS_EXECUTABLE
int main(int argc, char** argv) {
	struct args a = {0};
	int r = parse_args(&a, argc, argv);
	if (r)
		return r;

	r = doit(&a, getuid());
	if (r)
		return r;

	execvp(*a.command, a.command);
	fprintf(stderr, "Error: Could not exec %s: %s\n", *a.command, strerror(errno));
}

#else

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	(void) flags;
	pamhandle = pamh;
	struct args a = {0};
	int r = parse_args(&a, argc, (char**) argv);
	if (r)
		return PAM_SESSION_ERR;

	uid_t uid = -1;
	if (!a.explicit_user) {
		const char* user = NULL;
		r = pam_get_user(pamh, &user, NULL);
		if (r)
			return r;
		r = parse_user(user, &uid);
		if (r)
			return r;
	}

	r = doit(&a, uid);
	if (r)
		return PAM_SESSION_ERR;

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char** argv) {
	(void) pamh, (void) flags, (void) argc, (void) argv;
	return PAM_SUCCESS;
}
#endif
#endif
