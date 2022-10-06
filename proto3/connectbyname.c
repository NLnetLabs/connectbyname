/*
connectbyname.c

Implementation of connectbyname
*/

#if 0
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#endif

#include <assert.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/dns.h>

#include "connectbyname.h"

#define MAXADDRS	16
#define TIMEOUT_NS	  25000000	/* 25 ms */
#if 0
#undef TIMEOUT_NS
#define TIMEOUT_NS	5000000000	
#endif
#define US_PER_SEC	   1000000	/* Microseconds in a second */
#define NS_PER_SEC	1000000000	/* Nanoseconds in a second */

struct addrlist
{
	int timeout;
	int error;
	int socket;
	int selected;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	struct timespec endtime;
	struct event *event;
};

struct work_ctx
{
	unsigned port;			/* Port number to connect to */
	void (*user_cb)(int fd, void *ref);
	void *user_ref;

	unsigned state;
	struct evdns_request *evdns_ipv4;
	struct evdns_request *evdns_ipv6;
	struct addrlist alist[MAXADDRS];
	unsigned naddrs;
	struct addrlist *mlist[MAXADDRS];

	/* If IPv4 address arrive first, we wait a bit for the IPv6 addresses
	 * to arrive. If the time expires, we start connecting to the IPv4
	 * addresses.
	 */
	struct event *ipv6_to_event;
	struct timespec ipv6_timeout;

	/* Event for connect timeout */
	struct event *connect_to_event;

	struct cbn_context *base;
};

#define STATE_INITIAL			0
#define STATE_DNS			1
#define STATE_DNS_IPV4_CONNECTING	2
#define STATE_DNS_IPV6_WAITING		3
#define STATE_DNS_IPV6_CONNECTING	4
#define STATE_CONNECTING		5

static void dns_callback(int result, char type, int count, int ttl, 
	void *addresses, void *arg);
static void timeout_callback(evutil_socket_t fd, short events, void *ref);
static void connect_callback(evutil_socket_t fd, short events, void *ref);
static void connect_to_callback(evutil_socket_t fd, short events, void *ref);
static void merge_v4_v6(struct work_ctx *ctxp);
static void do_connect(struct work_ctx *ctxp);
static void ts_add_ns(struct timespec *tsp, long ns);
static void ts_sub(struct timespec *res,
	struct timespec *v1, struct timespec *v2);
static void tv_from_ts(struct timeval *tv, struct timespec *ts);

int cbn_init(struct cbn_context *cbn_ctx, struct event_base *event_base)
{
	memset(cbn_ctx, '\0', sizeof(*cbn_ctx));
	cbn_ctx->event_base= event_base;
	return 0;
}

int connectbyname_asyn(struct cbn_context *cbn_ctx,
	const char *hostname, const char *servname,
	void (*user_cb)(int fd, void *ref), void *user_ref, void **refp)
{
	int flags;
	unsigned long port_ul;
	char *next;
	struct servent *se;
	struct work_ctx *work_ctx;

	/* Parse servname */
	port_ul= strtoul(servname, &next, 10);
	if (next[0] == '\0')
	{
		if (port_ul == 0 || port_ul >= 0x10000)
		{
			/* XXX should convert error */
			return -1;
		}
		port_ul= htons(port_ul);
	}
	else
	{
		se= getservbyname(servname, "tcp");
		if (se == NULL)
			return -1;	/* XXX convert error */
		port_ul= se->s_port;
	}

	assert(cbn_ctx->event_base);
	if (!cbn_ctx->evdns_base)
	{
		cbn_ctx->evdns_base= evdns_base_new(cbn_ctx->event_base, EVDNS_BASE_INITIALIZE_NAMESERVERS);

		/* Should check for failure */
	}

	work_ctx= malloc(sizeof(*work_ctx));
	memset(work_ctx, '\0', sizeof(*work_ctx));
	work_ctx->base= cbn_ctx;
	work_ctx->port= port_ul;
	work_ctx->user_cb= user_cb;
	work_ctx->user_ref= user_ref;

	work_ctx->state= STATE_INITIAL;

	work_ctx->state= STATE_DNS;

	flags= 0;
	work_ctx->evdns_ipv4= evdns_base_resolve_ipv4(cbn_ctx->evdns_base,
		hostname, flags, dns_callback, work_ctx);
	work_ctx->evdns_ipv6= evdns_base_resolve_ipv6(cbn_ctx->evdns_base,
		hostname, flags, dns_callback, work_ctx);

	*refp= work_ctx;
	return 0;

#if 0
	int i, j, r, s, any, best, done, do_timeout, error, maxfd, 
		naddrs, prefer_ipv6, saved_r, sock;
	socklen_t socklen;
	long nsecdiff;
	struct addrinfo *res, *tres;
	struct addrinfo *reslist[MAXADDRS];
	struct addrlist *ap;
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

	printf("before sorting:\n");
	for (i= 0; i<naddrs; i++)
	{
		getnameinfo(reslist[i]->ai_addr, reslist[i]->ai_addrlen, 
			addrstr, sizeof(addrstr), NULL, 0, NI_NUMERICHOST);
		printf("%s\n", addrstr);
	}

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

	printf("after sorting:\n");
	for (i= 0; i<naddrs; i++)
	{
		getnameinfo(alist[i].ai->ai_addr, alist[i].ai->ai_addrlen, 
			addrstr, sizeof(addrstr), NULL, 0, NI_NUMERICHOST);
		printf("%s\n", addrstr);
	}

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
			fprintf(stderr, "%d: error %d\n", i, ap->error);
			if (ap->error)
			{
				continue;	/* This address already
						 * failed.
						 */
			}
			fprintf(stderr, "%d: socket %d\n", i, ap->socket);

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
					TIMEOUT_NS / NS_PER_SEC;
				ap->endtime.tv_nsec= now.tv_nsec +
					TIMEOUT_NS % NS_PER_SEC;
				if (ap->endtime.tv_nsec >= NS_PER_SEC)
				{
					ap->endtime.tv_nsec -= NS_PER_SEC;
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
					nsecdiff += NS_PER_SEC;
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
		fprintf(stderr, "select returned %d\n", r);

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
#endif
}

static void dns_callback(int result, char type, int count, int ttl, 
	void *addresses, void *arg)
{
	int i;
	struct work_ctx *ctxp;
	struct sockaddr_in *sin4p;
	struct sockaddr_in6 *sin6p;
	struct addrlist *alist;
	uint8_t (*addrs4)[4];
	uint8_t (*addrs6)[16];
	struct timespec timeout;
	char addrstr[INET6_ADDRSTRLEN];

	ctxp= arg;
	if (result != DNS_ERR_NONE)
	{
		/* Should handle DNS errors */
		fprintf(stderr, "dns_callback, result %d\n", result);
		return;
	}
	switch(type)
	{
	case DNS_IPv4_A:
		addrs4= addresses;
		for (i= 0, alist= &ctxp->alist[ctxp->naddrs]; i<count;
			i++, alist++)
		{
			if (ctxp->naddrs >= MAXADDRS)
				break;

			alist->error= 0;
			alist->socket= -1;

			sin4p= (struct sockaddr_in *)&alist->addr;
			memset(sin4p, '\0', sizeof(*sin4p));
			sin4p->sin_family= AF_INET;
			memcpy(&sin4p->sin_addr, addrs4[i],
				sizeof(sin4p->sin_addr));
			sin4p->sin_port= ctxp->port;
			alist->addrlen= sizeof(*sin4p);
			ctxp->naddrs++;
		}

		merge_v4_v6(ctxp);

		switch(ctxp->state)
		{
		case STATE_DNS:
			ctxp->state= STATE_DNS_IPV6_WAITING;
			ctxp->ipv6_to_event= evtimer_new(ctxp->base->event_base,
				timeout_callback, ctxp);
			clock_gettime(CLOCK_MONOTONIC, &timeout);
			timeout.tv_nsec += TIMEOUT_NS % NS_PER_SEC;
			timeout.tv_sec += TIMEOUT_NS / NS_PER_SEC;
			if (timeout.tv_nsec >= NS_PER_SEC)
			{
				timeout.tv_nsec -= NS_PER_SEC;
				timeout.tv_sec++;
			}
			ctxp->ipv6_timeout= timeout;

			/* The timeout callback will set the timer. */
			timeout_callback(-1, 0, ctxp);
			break;

		case STATE_DNS_IPV4_CONNECTING:
			ctxp->state= STATE_CONNECTING;

#if 0
			fprintf(stderr,
			"dns_callback: before do_connect, addresses:\n");
			for (i= 0; i<ctxp->naddrs; i++)
			{
				getnameinfo((struct sockaddr *)
					&ctxp->mlist[i]->addr,
					ctxp->mlist[i]->addrlen, 
					addrstr, sizeof(addrstr), NULL, 0,
					NI_NUMERICHOST);
				fprintf(stderr, "%s\n", addrstr);
			}
#endif
			do_connect(ctxp);
			break;

		default:
			fprintf(stderr,
				"dns_callback: unknown state %d (IPv4)\n",
				ctxp->state);
			return;
		}

		break;

	case DNS_IPv6_AAAA:
		addrs6= addresses;
		for (i= 0, alist= &ctxp->alist[ctxp->naddrs]; i<count;
			i++, alist++)
		{
			if (ctxp->naddrs >= MAXADDRS)
				break;

			alist->error= 0;
			alist->socket= -1;

			sin6p= (struct sockaddr_in6 *)&alist->addr;
			memset(sin6p, '\0', sizeof(*sin6p));
			sin6p->sin6_family= AF_INET6;
			memcpy(&sin6p->sin6_addr, addrs6[i],
				sizeof(sin6p->sin6_addr));
			sin6p->sin6_port= ctxp->port;
			alist->addrlen= sizeof(*sin6p);
			ctxp->naddrs++;
		}

		merge_v4_v6(ctxp);

		switch(ctxp->state)
		{
		case STATE_DNS:
			ctxp->state= STATE_DNS_IPV4_CONNECTING;
#if 0
			fprintf(stderr,
			"dns_callback: before do_connect, addresses:\n");
			for (i= 0; i<ctxp->naddrs; i++)
			{
				getnameinfo((struct sockaddr *)
					&ctxp->mlist[i]->addr,
					ctxp->mlist[i]->addrlen, 
					addrstr, sizeof(addrstr), NULL, 0,
					NI_NUMERICHOST);
				fprintf(stderr, "%s\n", addrstr);
			}
#endif
			do_connect(ctxp);
			break;

		case STATE_DNS_IPV6_WAITING:
			/* Cancel timer */
			evtimer_del(ctxp->ipv6_to_event);
			event_free(ctxp->ipv6_to_event);
			ctxp->ipv6_to_event= NULL;
			ctxp->state= STATE_CONNECTING;
#if 0
			fprintf(stderr,
			"dns_callback: before do_connect, addresses:\n");
			for (i= 0; i<ctxp->naddrs; i++)
			{
				getnameinfo((struct sockaddr *)
					&ctxp->mlist[i]->addr,
					ctxp->mlist[i]->addrlen, 
					addrstr, sizeof(addrstr), NULL, 0,
					NI_NUMERICHOST);
				fprintf(stderr, "%s\n", addrstr);
			}
#endif
			do_connect(ctxp);
			break;
			
		default:
			fprintf(stderr,
			"dns_callback: unknown state %d (IPv6)\n",
				ctxp->state);
			return;
		}

		break;

	default:
		fprintf(stderr, "dns_callback; unknown type %d\n", type);
		return;
	}
}

static void timeout_callback(evutil_socket_t fd, short events, void *ref)
{
	struct work_ctx *ctxp;
	struct timespec now;
	struct timeval timeout;

	ctxp= ref;
	clock_gettime(CLOCK_MONOTONIC, &now);

	if (now.tv_sec < ctxp->ipv6_timeout.tv_sec ||
		(now.tv_sec == ctxp->ipv6_timeout.tv_sec &&
		now.tv_nsec < ctxp->ipv6_timeout.tv_nsec))
	{
		/* Set timer */
		timeout.tv_sec= ctxp->ipv6_timeout.tv_sec - now.tv_sec;
		timeout.tv_usec= (ctxp->ipv6_timeout.tv_nsec - now.tv_nsec)/
			1000 + 1;

		if (timeout.tv_usec < 0)
		{
			timeout.tv_usec += US_PER_SEC;
			timeout.tv_sec--;
		}
		evtimer_add(ctxp->ipv6_to_event, &timeout);
		return;
	}

	/* The state should be STATE_DNS_IPV6_WAITING. Ignore other states */
	if (ctxp->state != STATE_DNS_IPV6_WAITING)
	{
		fprintf(stderr, "timeout_callback: bad state %d\n",
			ctxp->state);
		return;
	}

	/* Start connecting */
	ctxp->state= STATE_DNS_IPV6_CONNECTING;
	do_connect(ctxp);
}

static void connect_callback(evutil_socket_t fd, short events, void *ref)
{
	int i, r, error, sock;
	socklen_t socklen;
	struct work_ctx *ctxp;
	struct addrlist *ap;
	void (*user_cb)(int fd, void *ref);
	void *user_ref;

	ctxp= ref;

	/* Just look at all sockets */
	for (i= 0, ap= ctxp->alist; i<ctxp->naddrs; i++, ap++)
	{
		if (ap->socket == fd)
			break;
	}

	if (i >= ctxp->naddrs)
	{
		/* Weird. */
		fprintf(stderr, "connect_callback: socket not found\n");
		return;

	}

	/* Check for error */
	socklen= sizeof(error);
	r= getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &socklen);
	if (r == -1)
	{
		/* Weird */
		ap->error= errno;
		do_connect(ctxp);
		return;
	}
	if (error)
	{
		ap->error= error;
		do_connect(ctxp);
		return;
	}

	sock= ap->socket;
	ap->socket= -1;

	assert(ap->event);
	event_del(ap->event);
	event_free(ap->event);
	ap->event= NULL;

	/* Kill timers */
	if (ctxp->ipv6_to_event)
	{
		evtimer_del(ctxp->ipv6_to_event);
		event_free(ctxp->ipv6_to_event);
		ctxp->ipv6_to_event= NULL;
	}

	assert(ctxp->connect_to_event);
	evtimer_del(ctxp->connect_to_event);
	event_free(ctxp->connect_to_event);
	ctxp->connect_to_event= NULL;

	for (i= 0, ap= ctxp->alist; i<ctxp->naddrs; i++, ap++)
	{
		if (ap->socket == -1)
			continue;

		assert(ap->event);
		event_del(ap->event);
		event_free(ap->event);
		ap->event= NULL;

		close(ap->socket);
		ap->socket= -1;
	}

	/* Should deal with 
	struct evdns_request *evdns_ipv4;
	struct evdns_request *evdns_ipv6;
	*/

	user_cb= ctxp->user_cb;
	user_ref= ctxp->user_ref;

	/* Should free ctxp */

	(*user_cb)(sock, user_ref);
}

static void connect_to_callback(evutil_socket_t fd, short events, void *ref)
{
	struct work_ctx *ctxp;

	ctxp= ref;

	fprintf(stderr, "connect_to_callback: restarting connect\n");
	do_connect(ctxp);
}

static void merge_v4_v6(struct work_ctx *ctxp)
{
	int i, j, any, best, prefer_ipv6;
	struct addrlist *ap;

	for (i= 0, ap= ctxp->alist; i<ctxp->naddrs; i++, ap++)
		ap->selected= 0;

	/* Try to interleave IPv4 and IPv6 addresses */
	prefer_ipv6= 1;
	for (i= 0; i<ctxp->naddrs; i++)
	{
		best= -1;
		any= -1;
		for (j= 0, ap= ctxp->alist; j<ctxp->naddrs; j++, ap++)
		{
			if (ap->selected)
				continue;

			if (any == -1)
				any= j;
			if (prefer_ipv6)
			{
				if (ap->addr.ss_family == AF_INET6)
				{
					best= j;
					prefer_ipv6= 0;	/* IPv4 next time */
					break;
				}
			}
			else
			{
				if (ap->addr.ss_family == AF_INET)
				{
					best= j;
					prefer_ipv6= 1;	/* IPv6 next time */
					break;
				}
			}
		}
		if (best != -1)
		{
			ctxp->mlist[i]= &ctxp->alist[best];
			ctxp->alist[best].selected= 1;
			continue;
		}
		assert(any != -1);
		ctxp->mlist[i]= &ctxp->alist[any];
		ctxp->alist[any].selected= 1;
	}
}

static void do_connect(struct work_ctx *ctxp)
{
	int i, r, done, do_timeout;
	struct addrlist *ap;
	struct timespec now, timeout_ns;
	struct timeval timeout;

	done= 1;	/* Assume we are done. Will be cleared when
			 * there is work to do.
			 */
	do_timeout= 0;
	clock_gettime(CLOCK_MONOTONIC, &now);
	for (i= 0; i<ctxp->naddrs; i++)
	{
		ap= ctxp->mlist[i];

		if (ap->error)
		{
			continue;	/* This address already
					 * failed.
					 */
		}

		if (ap->socket == -1)
		{
			r= socket(ap->addr.ss_family, SOCK_STREAM, 0);
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

			r= connect(ap->socket, (struct sockaddr *)&ap->addr,
				ap->addrlen);
			if (r == 0)
			{
				/* This is weird, a nonblocking
				 * connect that succeeds. In any case,
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
			ap->endtime= now;
			ts_add_ns(&ap->endtime, TIMEOUT_NS);

			assert(!ap->event);
			ap->event= event_new(ctxp->base->event_base,
				ap->socket, EV_WRITE, connect_callback, ctxp);
			event_add(ap->event, NULL);
		}

		assert(ap->socket != -1 && ap->error == 0);
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

			ts_sub(&timeout_ns, &ap->endtime, &now);
			tv_from_ts(&timeout, &timeout_ns);
			do_timeout= 1;
			break;
		}
	}

	if (done)
	{
		if (i < ctxp->naddrs)
		{
			fprintf(stderr, "do_connect: found one\n");
			return;	/* Got something */
		}

		/* All addresses failed. */
		fprintf(stderr, "do_connect: all failed\n");
		assert(ctxp->alist[0].error);
		return;
	}

	if (do_timeout)
	{
		if (!ctxp->connect_to_event)
		{
			ctxp->connect_to_event=
				evtimer_new(ctxp->base->event_base,
				connect_to_callback, ctxp);
		}
		evtimer_add(ctxp->connect_to_event, &timeout);
	}

}

static void ts_add_ns(struct timespec *tsp, long ns)
{
	tsp->tv_sec += TIMEOUT_NS / NS_PER_SEC;
	tsp->tv_nsec += TIMEOUT_NS % NS_PER_SEC;
	if (tsp->tv_nsec >= NS_PER_SEC)
	{
		tsp->tv_nsec -= NS_PER_SEC;
		tsp->tv_sec++;
	}
}

static void ts_sub(struct timespec *res,
	struct timespec *v1, struct timespec *v2)
{
	res->tv_sec= v1->tv_sec-v2->tv_sec;
	res->tv_nsec= v1->tv_nsec-v2->tv_nsec;
	if (res->tv_nsec < 0)
	{
		res->tv_nsec += NS_PER_SEC;
		res->tv_sec--;
	}
}

static void tv_from_ts(struct timeval *tv, struct timespec *ts)
{
	tv->tv_sec= ts->tv_sec;
	tv->tv_usec= ts->tv_nsec/1000;
	if (ts->tv_nsec % 1000)
		tv->tv_usec++;	/* Round up */
}
