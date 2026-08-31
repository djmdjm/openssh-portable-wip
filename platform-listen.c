/*
 * Copyright (c) 2006 Darren Tucker.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "misc.h"
#include "platform.h"
#include "misc.h"
#include "xmalloc.h"

#include "openbsd-compat/openbsd-compat.h"

void
platform_pre_listen(void)
{
#ifdef LINUX_OOM_ADJUST
	/* Adjust out-of-memory killer so listening process is not killed */
	oom_adjust_setup();
#endif
#ifdef LINUX_MEMLOCK_ONFAULT
	/*
	 * Protect ourselves against kcompactd so that we are able to process
	 * new connections while it is active and migrating pages.
	 */
	memlock_onfault_setup();
#endif
}

void
platform_post_listen(void)
{
#ifdef SYSTEMD_NOTIFY
	ssh_systemd_notify_ready();
#endif
}

void
platform_pre_fork(void)
{
#ifdef USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_pre_fork();
#endif
}

void
platform_pre_restart(void)
{
#ifdef SYSTEMD_NOTIFY
	ssh_systemd_notify_reload();
#endif
#ifdef LINUX_OOM_ADJUST
	oom_adjust_restore();
#endif
}

void
platform_post_fork_parent(pid_t child_pid)
{
#ifdef USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_parent(child_pid);
#endif
}

void
platform_post_fork_child(void)
{
#ifdef USE_SOLARIS_PROCESS_CONTRACTS
	solaris_contract_post_fork_child();
#endif
#ifdef LINUX_OOM_ADJUST
	oom_adjust_restore();
#endif
}

void platform_pre_session_start(void)
{
#ifdef LINUX_MEMLOCK_ONFAULT
	/*
	 * Memlock flags are dropped on fork, lock the memory again so that the
	 * child connection is also protected against kcompactd.
	 */
	memlock_onfault_setup();
#endif
}

int
platform_socket_activation(int **socksp, int *num_socksp, int maxsocks)
{
#ifdef USE_SYSTEMD_SOCKET_ACTIVATION
	const char *cp, *errstr;
	int i, pid, nfds, fd, maxfd = -1;

	if ((cp = getenv("LISTEN_PID")) == NULL)
		return -1;

	/* Validate $LISTEN_PID */
	pid = (int)strtonum(cp, 1, INT_MAX, &errstr);
	if (errstr != NULL)
		fatal_f("invalid $LISTEN_PID contents: %s", errstr);
	if (pid != getpid())
		fatal_f("bad LISTEN_PID: %d vs pid %d", pid, getpid());

	/* Capture $LISTEN_FDS sockets */
	if ((cp = getenv("LISTEN_FDS")) == NULL)
		fatal_f("cannot listen: LISTEN_PID set without LISTEN_FDS");
	nfds = (int)strtonum(cp, 1, maxsocks, &errstr);
	if (errstr != NULL)
		fatal_f("invalid $LISTEN_FDS contents: %s", errstr);

	for (i = 0; i < nfds; i++) {
		fd = 3 + i;
		debug_f("using fd %d", fd);
		if (set_nonblock(fd) != 0)
			fatal_f("cannot listen: bad file descriptor %d", fd);
		if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
			fatal_f("cannot listen: fcntl fd %d: %s", fd,
			    strerror(errno));
		}
		*socksp = xrecallocarray(*socksp, *num_socksp, *num_socksp + 1,
		    sizeof(**socksp));
		(*socksp)[(*num_socksp)++] = fd;
		maxfd = fd;
	}
	debug_f("%d sockets from socket activation", nfds);
	return maxfd;
#else
	return -1;
#endif
}
