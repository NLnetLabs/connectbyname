/*
connectbyname.c

Implementation of connectbyname
*/

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "connectbyname.h"

#define MAXADDRS	16
#define TIMEOUT_NS	25000000	/* 25 ms */
#undef TIMEOUT_NS
#define TIMEOUT_NS	5000000	

struct addrlist
{
	int timeout;
	int error;
	int socket;
	struct addrinfo *ai;
	struct timespec endtime;
};

int cbn_init(struct cbn_context *cbn_ctx)
{
	memset(cbn_ctx, '\0', sizeof(cbn_ctx));
	return 0;
}

int connectbyname(struct cbn_context *cbn_ctx,
	const char *hostname, const char *servname, int *fdp)
{
	int i, j, r, s, any, best, done, do_timeout, error, maxfd, 
		naddrs, prefer_ipv6, saved_r, sock;
	socklen_t socklen;
	long nsecdiff;
	struct addrinfo *res, *tres;
	struct addrinfo *reslist[MAXADDRS];
	struct addrlist *ap;
	struct addrlist alist[MAXADDRS];
	struct addrinfo hints;
	char addrstr[INET6_ADDRSTRLEN];
	fd_set wrset, errset;
	struct timeval timeout;
	struct timespec now;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_STREAM;

	r= getaddrinfo(hostname, servname, &hints, &res);
	if (r != 0)
		return -1;	/* XXX convert error */

	/* Copy res entries to reslist */
	for (naddrs= 0, tres= res; naddrs < MAXADDRS, tres;
		naddrs++, tres= tres->ai_next)
	{
		reslist[naddrs]= tres;
	}

#if 0
	printf("before sorting:\n");
	for (i= 0; i<naddrs; i++)
	{
		getnameinfo(reslist[i]->ai_addr, reslist[i]->ai_addrlen, 
			addrstr, sizeof(addrstr), NULL, 0, NI_NUMERICHOST);
		printf("%s\n", addrstr);
	}
#endif

	/* Try to interleave IPv4 and IPv6 addresses */
	prefer_ipv6= 1;
	for (i= 0; i<naddrs; i++)
	{
		alist[i].error= 0;
		alist[i].socket= -1;

		best= -1;
		any= -1;
		for (j= 0; j<naddrs; j++)
		{
			tres= reslist[j];
			if (!tres)
				continue;
			if (any == -1)
				any= j;
			if (prefer_ipv6)
			{
				if (tres->ai_family == AF_INET6)
				{
					best= j;
					prefer_ipv6= 0;	/* IPv4 next time */
					break;
				}
			}
			else
			{
				if (tres->ai_family == AF_INET)
				{
					best= j;
					prefer_ipv6= 1;	/* IPv6 next time */
					break;
				}
			}
		}
		if (best != -1)
		{
			alist[i].ai= reslist[best];
			reslist[best]= NULL;
			continue;
		}
		assert(any != -1);
		alist[i].ai= reslist[any];
		reslist[any]= NULL;
	}

#if 0
	printf("after sorting:\n");
	for (i= 0; i<naddrs; i++)
	{
		getnameinfo(alist[i].ai->ai_addr, alist[i].ai->ai_addrlen, 
			addrstr, sizeof(addrstr), NULL, 0, NI_NUMERICHOST);
		printf("%s\n", addrstr);
	}
#endif

	for(;;)
	{
		done= 1;	/* Assume we are done. Will be cleared when
				 * there is work to do.
				 */
		FD_ZERO(&wrset);
		FD_ZERO(&errset);
		maxfd= 0;
		do_timeout= 0;
		clock_gettime(CLOCK_MONOTONIC, &now);
		for (i= 0, ap= alist; i<naddrs; i++, ap++)
		{
			if (ap->error)
			{
				continue;	/* This address already
						 * failed.
						 */
			}

			if (ap->socket == -1)
			{
				r= socket(ap->ai->ai_family,
					ap->ai->ai_socktype, 
					ap->ai->ai_protocol);
				if (r == -1)
				{
					ap->error= errno;
					continue;
				}

				ap->socket= r;

				/* Switch to nonblocking */
				fcntl(ap->socket, F_SETFL,
					fcntl(ap->socket, F_GETFL) |
					O_NONBLOCK);

				r= connect(ap->socket, ap->ai->ai_addr,
					ap->ai->ai_addrlen);
				if (r == 0)
				{
					/* This is weird, a nonblocking
					 * connect that succeeds. In any,
					 * we got what we wanted.
					 */
					done= 1; /* signal that we are done */
					break;
				}
				else if (errno == EINPROGRESS)
				{
					/* This is what we expect, fall
					 * through.
					 */
				}
				else
				{
					/* Some kind of error */
					ap->error= errno;
					continue;
				}

				ap->timeout= 0;
				ap->endtime.tv_sec= now.tv_sec + 
					TIMEOUT_NS / 1000000000;
				ap->endtime.tv_nsec= now.tv_nsec +
					TIMEOUT_NS % 1000000000;
				if (ap->endtime.tv_nsec >= 1000000000)
				{
					ap->endtime.tv_nsec -= 1000000000;
					ap->endtime.tv_sec++;
				}
			}

			assert(ap->socket != -1 && ap->error == 0);
			FD_SET(ap->socket, &wrset);
			FD_SET(ap->socket, &errset);
			if (ap->socket > maxfd)
				maxfd= ap->socket;
			done= 0;

			if (!ap->timeout)
			{
				if (ap->endtime.tv_sec < now.tv_sec ||
					(ap->endtime.tv_sec == now.tv_sec &&
					ap->endtime.tv_nsec <= now.tv_nsec))
				{
					/* We got a timeout, move to the
					 * next address.
					 */
					ap->timeout= 1;
					continue;
				}

				timeout.tv_sec= ap->endtime.tv_sec-now.tv_sec;
				nsecdiff= ap->endtime.tv_nsec-now.tv_nsec;
				if (nsecdiff < 0)
				{
					nsecdiff += 1000000000;
					timeout.tv_sec--;
				}
				timeout.tv_usec= nsecdiff/1000+1;
				do_timeout= 1;
				break;
			}
		}

		if (done)
		{
			if (i < naddrs)
				break;	/* Got something */

			/* All addresses failed. */
			assert(alist[0].error);
			break;
		}

		r= select(maxfd+1, NULL, &wrset, &errset,
			do_timeout ? &timeout : NULL);

		if (r > 0)
		{
			/* Just look at all sockets */
			for (i= 0, ap= alist; i<naddrs; i++, ap++)
			{
				if (ap->error)
					continue;
				sock= ap->socket;
				if (sock == -1)
					continue;
				if (FD_ISSET(sock, &wrset))
				{
					/* Check for error */
					socklen= sizeof(error);
					r= getsockopt(sock, SOL_SOCKET,
						SO_ERROR, &error, &socklen);
					if (r == -1)
					{
						/* Weird */
						ap->error= errno;
						continue;
					}
					if (error)
					{
						ap->error= error;
						continue;
					}

					/* No error, got one */
					break;

				}
				if (FD_ISSET(sock, &errset))
				{
					/* What do we now? */
					fprintf(stderr, "what about errset?\n");
					abort();
				}
			}

			if (i<naddrs)
				break;
		}

		/* Try again */
	}

	freeaddrinfo(res);
	sock= -1;
	if (i < naddrs)
	{
		sock= alist[i].socket;
		alist[i].socket= -1;
	}
	for (i= 0, ap= alist; i<naddrs; i++, ap++)
	{
		if (ap->socket != -1)
		{
			close(ap->socket);
			ap->socket= -1;
		}
	}
	if (sock != -1)
	{
		/* Switch socket back to blocking */
		fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) & ~O_NONBLOCK);
		*fdp= sock;
		return 0;	/* Success */
	}

	/* Should convert error to result value */
	return -1;
	
#if 0
	XXX
	tres= res;
	for (tres= res; tres; tres= tres->ai_next)
	{
		s= socket(tres->ai_family, tres->ai_socktype,
			tres->ai_protocol);
		if (s == -1)
		{
			saved_r= -1;	/* Should convert errno */
			continue;
		}
		r= connect(s, tres->ai_addr, tres->ai_addrlen);
		if (r == -1)
		{
			saved_r= -1;	/* Should convert errno */
			close(s);
			s= -1;
			continue;
		}
	
		/* Done */
		break;
	}
	freeaddrinfo(res);
	if (tres)
	{
		*fdp= s;
		return 0;	/* Success */
	}
	return saved_r;
#endif
}
