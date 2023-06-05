#include <stdlib.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

#include "prelude.h"
#include "vec.h"

extern pam_handle_t* pamhandle;

INTERNAL struct ptrvec ptrvec_new(size_t cap) {
	if (!cap)
		return (struct ptrvec) {};
	cap = (cap + 1) / 2 * 2; // only use multiple of 16 bytes (minimum granularity for glibc malloc)
	void* ptr = malloc(cap * sizeof(void*));
	if (!ptr) {
		log_err("Could not allocate %zu bytes: %s", sizeof(void*) * cap, strerror(errno));
		return (struct ptrvec) {
			.cap = cap,
			.error = 1,
		};
	}
	return (struct ptrvec) {
		.cap = cap,
		.ptr = ptr,
	};
}

INTERNAL int ptrvec_append(struct ptrvec* v, void* e) {
	if (v->len + 1 > v->cap) {
		// increment in steps of two, since glibc's malloc usually works on 16 byte granularity anyway
		size_t new_cap = v->cap <= 2 ? v->cap + 2 : v->cap * 1.5;
		new_cap = (new_cap + 1) / 2 * 2; // round up to multiple of two
		void *new_ptr = realloc(v->ptr, new_cap * sizeof(void*));
		if (!new_ptr) {
			log_err("Could not reallocate to %zu bytes: %s", sizeof(void*) * new_cap, strerror(errno));
			return -1;
		}
		v->cap = new_cap;
		v->ptr = new_ptr;
	}
	v->ptr[v->len++] = e;
	return 0;
}

INTERNAL int ptrvec_resize_to_fit(struct ptrvec* v) {
	if (v->len + 1 != v->cap) {
		void *new_ptr = realloc(v->ptr, (v->len + 1) * sizeof(void*));
		if (!new_ptr) {
			log_err("Could not reallocate to %zu bytes: %s", sizeof(void*) * (v->len + 1), strerror(errno));
			return -1;
		}
		v->cap = v->len + 1;
		v->ptr = new_ptr;
	}
	v->ptr[v->len] = NULL;
	return 0;
}

INTERNAL void ptrvec_cleanup(struct ptrvec* v) {
	if (!v->ptr)
		return;
	for (size_t i = 0; i < v->len; i++) {
		free(v->ptr[i]);
	}
	free(v->ptr);
}


INTERNAL struct intvec intvec_new(size_t cap) {
	if (!cap)
		return (struct intvec) {};
	cap = (cap + 3) / 4 * 4; // round up ti multiple for four
	void* ptr = malloc(cap * sizeof(void*));
	if (!ptr) {
		log_err("Could not allocate %zu bytes: %s", sizeof(void*) * cap, strerror(errno));
		return (struct intvec) {
			.cap = cap,
			.error = 1,
		};
	}
	return (struct intvec) {
		.cap = cap,
		.ptr = ptr,
	};
}

INTERNAL int intvec_append(struct intvec* v, unsigned e) {
	if (v->len + 1 > v->cap) {
		size_t new_cap = v->cap <= 4 ? v->cap + 1 : v->cap * 1.5;
		new_cap = (new_cap + 3) / 4 * 4; // round up to multiple of four
		void *new_ptr = realloc(v->ptr, new_cap * sizeof(void*));
		if (!new_ptr) {
			log_err("Could not reallocate to %zu bytes: %s", sizeof(void*) * new_cap, strerror(errno));
			return -1;
		}
		v->cap = new_cap;
		v->ptr = new_ptr;
	}
	v->ptr[v->len++] = e;
	return 0;
}

INTERNAL int intvec_resize_to_fit(struct intvec* v) {
	if (v->len != v->cap) {
		void *new_ptr = realloc(v->ptr, (v->len) * sizeof(void*));
		if (!new_ptr) {
			log_err("Could not reallocate to %zu bytes: %s", sizeof(void*) * (v->len), strerror(errno));
			return -1;
		}
		v->cap = v->len + 1;
		v->ptr = new_ptr;
	}
	return 0;
}

INTERNAL void intvec_cleanup(struct intvec* v) {
	if (!v->ptr)
		return;
	free(v->ptr);
}

