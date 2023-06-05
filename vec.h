#pragma once
#include <stddef.h>

struct ptrvec {
	void** ptr;
	size_t len, cap;
	int error;
};

struct ptrvec ptrvec_new(size_t cap);
int ptrvec_append(struct ptrvec* v, void* e);
int ptrvec_resize_to_fit(struct ptrvec* v);
void ptrvec_cleanup(struct ptrvec* v);

struct intvec {
	unsigned* ptr;
	size_t len, cap;
	int error;
};

struct intvec intvec_new(size_t cap);
int intvec_append(struct intvec* v, unsigned e);
int intvec_resize_to_fit(struct intvec* v);
void intvec_cleanup(struct intvec* v);
