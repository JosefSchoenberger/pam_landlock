#include <syslog.h>

#ifdef AS_EXECUTABLE
#include <stdio.h>
#define pam_syslog(h, e, f, ...) \
	fprintf(stderr, "%s: " f "\n", e == LOG_ERR ? "Error" : e == LOG_WARNING ? "Warning" : e == LOG_INFO ? "Info" : e == LOG_DEBUG ? "Debug" : e == LOG_NOTICE ? "Notice" : "Unknown" __VA_OPT__(,) __VA_ARGS__)
#undef pam_error
#define pam_error(...)
#endif

#define INTERNAL __attribute__((visibility("hidden")))

#include <security/pam_appl.h>
extern pam_handle_t *pamhandle;

#define log_err(fmt, ...) do {\
	pam_syslog(pamhandle, LOG_ERR, fmt __VA_OPT__(,) __VA_ARGS__); \
	pam_error(pamhandle, "pam_landlock ERROR: " fmt __VA_OPT__(,) __VA_ARGS__); } while(0)
