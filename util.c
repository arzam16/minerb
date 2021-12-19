/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012 Luke Dashjr
 * Copyright 2012-2020 pooler
 * Copyright 2017 Pieter Wuille
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#define _GNU_SOURCE
#include "cpuminer-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#if defined(WIN32)
#include <winsock2.h>
#include <mstcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif
#include "compat.h"
#include "miner.h"
#include "elist.h"

struct thread_q {
	struct list_head	q;

	bool frozen;

	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
};

void applog(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

#ifdef HAVE_SYSLOG_H
	if (use_syslog) {
		va_list ap2;
		char *buf;
		int len;
		
		va_copy(ap2, ap);
		len = vsnprintf(NULL, 0, fmt, ap2) + 1;
		va_end(ap2);
		buf = alloca(len);
		if (vsnprintf(buf, len, fmt, ap) >= 0)
			syslog(prio, "%s", buf);
	}
#else
	if (0) {}
#endif
	else {
		char *f;
		int len;
		time_t now;
		struct tm tm, *tm_p;

		time(&now);

		pthread_mutex_lock(&applog_lock);
		tm_p = localtime(&now);
		memcpy(&tm, tm_p, sizeof(tm));
		pthread_mutex_unlock(&applog_lock);

		len = 40 + strlen(fmt) + 2;
		f = alloca(len);
		sprintf(f, "[%d-%02d-%02d %02d:%02d:%02d] %s\n",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec,
			fmt);
		pthread_mutex_lock(&applog_lock);
		vfprintf(stderr, f, ap);	/* atomic write to stderr */
		fflush(stderr);
		pthread_mutex_unlock(&applog_lock);
	}
	va_end(ap);
}

void bin2hex(char *s, const unsigned char *p, size_t len)
{
	int i;
	for (i = 0; i < len; i++)
		sprintf(s + (i * 2), "%02x", (unsigned int) p[i]);
}

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */
int timeval_subtract(struct timeval *result, struct timeval *x,
	struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating Y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 * `tv_usec' is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}

bool fulltest(const uint32_t *hash, const uint32_t *target)
{
	int i;
	bool rc = true;
	
	for (i = 7; i >= 0; i--) {
		if (hash[i] > target[i]) {
			rc = false;
			break;
		}
		if (hash[i] < target[i]) {
			rc = true;
			break;
		}
	}

	if (opt_debug) {
		uint32_t hash_be[8], target_be[8];
		char hash_str[65], target_str[65];
		
		for (i = 0; i < 8; i++) {
			be32enc(hash_be + i, hash[7 - i]);
			be32enc(target_be + i, target[7 - i]);
		}
		bin2hex(hash_str, (unsigned char *)hash_be, 32);
		bin2hex(target_str, (unsigned char *)target_be, 32);

		applog(LOG_DEBUG, "DEBUG: %s\nHash:   %s\nTarget: %s",
			rc ? "hash <= target"
			   : "hash > target (false positive)",
			hash_str,
			target_str);
	}

	return rc;
}

struct thread_q *tq_new(void)
{
	struct thread_q *tq;

	tq = calloc(1, sizeof(*tq));
	if (!tq)
		return NULL;

	INIT_LIST_HEAD(&tq->q);
	pthread_mutex_init(&tq->mutex, NULL);
	pthread_cond_init(&tq->cond, NULL);

	return tq;
}

static void tq_freezethaw(struct thread_q *tq, bool frozen)
{
	pthread_mutex_lock(&tq->mutex);

	tq->frozen = frozen;

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);
}

void tq_freeze(struct thread_q *tq)
{
	tq_freezethaw(tq, true);
}
