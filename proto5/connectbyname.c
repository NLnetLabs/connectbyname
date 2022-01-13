/*
connectbyname.c

Implementation of connectbyname
*/

#include <assert.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <event2/bufferevent_ssl.h>

#include <openssl/ssl.h>

#include <getdns/getdns_ext_libevent.h>

#include "connectbyname.h"

#define MAXADDRS	16
#define TIMEOUT_NS	  25000000	/* 25 ms */
#if 1
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
	struct bufferevent *bev;
};

struct work_ctx
{
	unsigned port;			/* Port number to connect to */
	cbn_callback_T user_cb;
	void *user_ref;

	unsigned state;
	getdns_transaction_t trans_id_ipv4;
	getdns_transaction_t trans_id_ipv6;
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

	SSL_CTX *tls_ctx;

	struct cbn_context *base;
};

#define STATE_INITIAL			0
#define STATE_DNS			1
#define STATE_DNS_IPV4_CONNECTING	2
#define STATE_DNS_IPV6_WAITING		3
#define STATE_DNS_IPV6_CONNECTING	4
#define STATE_CONNECTING		5

static void dns_callback(getdns_context *context,
	getdns_callback_type_t callback_type,
	getdns_dict *response,
	void *userarg,
	getdns_transaction_t transaction_id);
static void timeout_callback(evutil_socket_t fd, short events, void *ref);
static void connect_callback(evutil_socket_t fd, short events, void *ref);
static void connect_to_callback(evutil_socket_t fd, short events, void *ref);
static void read_callback(struct bufferevent *bev, void *ref);
static void write_callback(struct bufferevent *bev, void *ref);
static void event_callback(struct bufferevent *bev, short what, void *ref);
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

void cbn_clean(struct cbn_context *cbn_ctx)
{
	getdns_context_destroy(cbn_ctx->getdns_ctx);
	cbn_ctx->getdns_ctx= NULL;
	cbn_ctx->event_base= NULL;
}

int connectbyname_asyn(struct cbn_context *cbn_ctx,
	const char *hostname, const char *servname,
	cbn_callback_T user_cb, void *user_ref, void **refp)
{
	int flags;
	getdns_return_t gdns_r;
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

	gdns_r= getdns_context_create(&cbn_ctx->getdns_ctx, 1);
	if (gdns_r != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr, "getdns_context_create failed\n");
		return -1;
	}

	gdns_r= getdns_extension_set_libevent_base(cbn_ctx->getdns_ctx,
		cbn_ctx->event_base);
	if (gdns_r != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr, "getdns_context_create failed\n");
		return -1;
	}
	
	work_ctx= malloc(sizeof(*work_ctx));
	fprintf(stderr, "connectbyname_asyn: work_ctx = %p\n", work_ctx);
	memset(work_ctx, '\0', sizeof(*work_ctx));
	work_ctx->base= cbn_ctx;
	work_ctx->port= port_ul;
	work_ctx->user_cb= user_cb;
	work_ctx->user_ref= user_ref;

	work_ctx->state= STATE_INITIAL;

	work_ctx->state= STATE_DNS;
	gdns_r= getdns_general(cbn_ctx->getdns_ctx,
		hostname, GETDNS_RRTYPE_AAAA,
		NULL, work_ctx, &work_ctx->trans_id_ipv6,
		dns_callback);
	if (gdns_r != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr, "getdns_general failed\n");
		return -1;
	}
	gdns_r= getdns_general(cbn_ctx->getdns_ctx,
		hostname, GETDNS_RRTYPE_A,
		NULL, work_ctx, &work_ctx->trans_id_ipv4,
		dns_callback);
	if (gdns_r != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr, "getdns_general failed\n");
		return -1;
	}

	*refp= work_ctx;
	return 0;
}

void connectbyname_free(void *ref)
{
	struct work_ctx *ctxp;

	ctxp= ref;
	fprintf(stderr, "connectbyname_free: ctxp = %p\n", ctxp);

	/* We should check what needs to be freed or canceled */

	free(ctxp);
	ctxp= NULL;
}

static void dns_callback(getdns_context *context,
	getdns_callback_type_t callback_type,
	getdns_dict *response,
	void *userarg,
	getdns_transaction_t transaction_id)
{
#if 0
	uint8_t (*addrs4)[4];
	uint8_t (*addrs6)[16];
#endif
	int i, got_ipv4, got_ipv6;
	getdns_return_t gdns_r;
	size_t len;
	struct work_ctx *ctxp;
	getdns_list *answer_list;
	getdns_dict *addr_dict;
	getdns_bindata *addr_type;
	getdns_bindata *addr_data;
	struct addrlist *alist;
	struct sockaddr_in *sin4p;
	struct sockaddr_in6 *sin6p;
	struct timespec timeout;
	char addrstr[INET6_ADDRSTRLEN];

	ctxp= userarg;
	if (callback_type != GETDNS_CALLBACK_COMPLETE)
	{
		/* Should handle DNS errors */
		fprintf(stderr, "dns_callback, callback_type %d\n",
			callback_type);
		goto cleanup;
	}

#if 0
	printf("dns_callback: got\n");
	printf("%s\n", getdns_pretty_print_dict(response));
#endif
	
	gdns_r= getdns_dict_get_list(response, "just_address_answers",
		&answer_list);
	if (gdns_r != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr,
		"dns_callback: nothing for 'just_address_answers': %d\n",
			gdns_r);
		goto cleanup;
	}
	gdns_r= getdns_list_get_length(answer_list, &len);
	if (gdns_r != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr,
		"dns_callback: no length for 'just_address_answers': %d\n",
			gdns_r);
		goto cleanup;
	}
	printf("len %d\n", len);
	got_ipv4= 0;
	got_ipv6= 0;
	for (i= 0; i<len; i++)
	{
		gdns_r= getdns_list_get_dict(answer_list, i, &addr_dict);
		if (gdns_r != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
			"dns_callback: no dict at %d: %d\n", i, gdns_r);
			goto cleanup;
		}
		gdns_r= getdns_dict_get_bindata(addr_dict, "address_type",
			&addr_type);
		if (gdns_r != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
			"dns_callback: address_type at %d: %d\n", i, gdns_r);
			goto cleanup;
		}
		gdns_r= getdns_dict_get_bindata(addr_dict, "address_data",
			&addr_data);
		if (gdns_r != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
			"dns_callback: address_data at %d: %d\n", i, gdns_r);
			goto cleanup;
		}
		fprintf(stderr, "dns_callback: %d type %.*s\n", i,
			addr_type->size, addr_type->data);

		if (addr_type->size != 4)
		{
			/* Weird address type */
			continue;
		}

		if (strncmp(addr_type->data, "IPv4", 4) == 0)
		{
			got_ipv4= 1;
			if (ctxp->naddrs >= MAXADDRS)
				continue;

			alist= &ctxp->alist[ctxp->naddrs];

			alist->error= 0;
			alist->socket= -1;

			sin4p= (struct sockaddr_in *)&alist->addr;
			memset(sin4p, '\0', sizeof(*sin4p));
			sin4p->sin_family= AF_INET;
			memcpy(&sin4p->sin_addr, addr_data->data,
				sizeof(sin4p->sin_addr));
			sin4p->sin_port= ctxp->port;
			alist->addrlen= sizeof(*sin4p);
			ctxp->naddrs++;
		}
		else if (strncmp(addr_type->data, "IPv6", 4) == 0)
		{
			got_ipv6= 1;
			if (ctxp->naddrs >= MAXADDRS)
				continue;

			alist= &ctxp->alist[ctxp->naddrs];

			alist->error= 0;
			alist->socket= -1;

			sin6p= (struct sockaddr_in6 *)&alist->addr;
			memset(sin6p, '\0', sizeof(*sin6p));
			sin6p->sin6_family= AF_INET6;
			memcpy(&sin6p->sin6_addr, addr_data->data,
				sizeof(sin6p->sin6_addr));
			sin6p->sin6_port= ctxp->port;
			alist->addrlen= sizeof(*sin6p);
			ctxp->naddrs++;
		}
		else
		{
			/* Weird address type */
			continue;
		}
	}

	merge_v4_v6(ctxp);

	if (got_ipv4)
	{
		switch(ctxp->state)
		{
		case STATE_DNS:
			ctxp->state= STATE_DNS_IPV6_WAITING;
			ctxp->ipv6_to_event= evtimer_new(ctxp->base->event_base,
				timeout_callback, ctxp);
			clock_gettime(CLOCK_MONOTONIC, &timeout);
			fprintf(stderr, "dns_callback: now %d.%09d\n",
				timeout.tv_sec, timeout.tv_nsec);
			timeout.tv_nsec += TIMEOUT_NS % NS_PER_SEC;
			timeout.tv_sec += TIMEOUT_NS / NS_PER_SEC;
			fprintf(stderr, "dns_callback: timeout %d.%09d\n",
				timeout.tv_sec, timeout.tv_nsec);
			if (timeout.tv_nsec >= NS_PER_SEC)
			{
				timeout.tv_nsec -= NS_PER_SEC;
				timeout.tv_sec++;
			}
			fprintf(stderr, "dns_callback: timeout %d.%09d\n",
				timeout.tv_sec, timeout.tv_nsec);
			ctxp->ipv6_timeout= timeout;

			/* The timeout callback will set the timer. */
			timeout_callback(-1, 0, ctxp);
			break;

		case STATE_DNS_IPV4_CONNECTING:
			ctxp->state= STATE_CONNECTING;

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
			do_connect(ctxp);
			break;

		default:
			fprintf(stderr,
				"dns_callback: unknown state %d (IPv4)\n",
				ctxp->state);
			goto cleanup;
		}
	}
	if (got_ipv6)
	{
		switch(ctxp->state)
		{
		case STATE_DNS:
			ctxp->state= STATE_DNS_IPV4_CONNECTING;
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
			do_connect(ctxp);
			break;

		case STATE_DNS_IPV6_WAITING:
			/* Cancel timer */
			evtimer_del(ctxp->ipv6_to_event);
			event_free(ctxp->ipv6_to_event);
			ctxp->ipv6_to_event= NULL;
			ctxp->state= STATE_CONNECTING;
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
			do_connect(ctxp);
			break;
			
		default:
			fprintf(stderr,
			"dns_callback: unknown state %d (IPv6)\n",
				ctxp->state);
			goto cleanup;
		}
	}
cleanup:
	getdns_dict_destroy(response);
	response= NULL;
}

static void timeout_callback(evutil_socket_t fd, short events, void *ref)
{
	struct work_ctx *ctxp;
	struct timespec now;
	struct timeval timeout;

	ctxp= ref;
	clock_gettime(CLOCK_MONOTONIC, &now);
	fprintf(stderr, "timeout_callback: now %d.%09d\n",
		now.tv_sec, now.tv_nsec);
	fprintf(stderr, "timeout_callback: target %d.%09d\n",
		ctxp->ipv6_timeout.tv_sec, ctxp->ipv6_timeout.tv_nsec);

	if (now.tv_sec < ctxp->ipv6_timeout.tv_sec ||
		(now.tv_sec == ctxp->ipv6_timeout.tv_sec &&
		now.tv_nsec < ctxp->ipv6_timeout.tv_nsec))
	{
		/* Set timer */
		timeout.tv_sec= ctxp->ipv6_timeout.tv_sec - now.tv_sec;
		timeout.tv_usec= (ctxp->ipv6_timeout.tv_nsec - now.tv_nsec)/
			1000 + 1;

		fprintf(stderr, "timeout %d.%06d\n",
			timeout.tv_sec, timeout.tv_usec);
		if (timeout.tv_usec < 0)
		{
			timeout.tv_usec += US_PER_SEC;
			timeout.tv_sec--;
		}
		fprintf(stderr, "timeout %d.%06d\n",
			timeout.tv_sec, timeout.tv_usec);
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
	SSL *tls;

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

	assert(ap->event);
	event_del(ap->event);
	event_free(ap->event);
	ap->event= NULL;

	fprintf(stderr,  "connect_callback: starting SSL for fd %d\n", sock);

	if (!ctxp->tls_ctx)
	{
		ctxp->tls_ctx= SSL_CTX_new(TLS_method());
	}

	tls= SSL_new(ctxp->tls_ctx);

	assert(!ap->bev);
	ap->bev= bufferevent_openssl_socket_new(ctxp->base->event_base,
		sock, tls, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);

	bufferevent_setcb(ap->bev, read_callback, write_callback, 
		event_callback, ctxp);


}

static void connect_to_callback(evutil_socket_t fd, short events, void *ref)
{
	struct work_ctx *ctxp;

	ctxp= ref;

	fprintf(stderr, "connect_to_callback: restarting connect\n");
	do_connect(ctxp);
}

static void read_callback(struct bufferevent *bev, void *ctx)
{
	fprintf(stderr, "in read_callback\n");
}

static void write_callback(struct bufferevent *bev, void *ctx)
{
	fprintf(stderr, "in write_callback\n");
}

static void event_callback(struct bufferevent *bev, short what, void *ref)
{
	int i;
	struct work_ctx *ctxp;
	struct addrlist *ap;
	struct bufferevent *lbev;

	ctxp= ref;

	fprintf(stderr, "in event_callback, what 0x%x\n", what);

	if (what != BEV_EVENT_CONNECTED)
	{
		fprintf(stderr,
			"event_callback, TLS connect failed with 0x%x\n",
			what);
		
	}

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

	/* Find bev */
	for (i= 0, ap= ctxp->alist; i<ctxp->naddrs; i++, ap++)
	{
		if (ap->bev == bev)
		{
			/* Found the right event */
			ap->bev= NULL;
			ap->socket= -1;
			continue;
		}
		if (!ap->bev)
		{
			if (ap->socket != -1)
			{
				assert(ap->event);
				event_del(ap->event);
				event_free(ap->event);
				ap->event= NULL;

				close(ap->socket);
				ap->socket= -1;
			}
			continue;
		}

		lbev= ap->bev;
		ap->bev= NULL;
		bufferevent_free(lbev);
		lbev= NULL;
	}

	ctxp->user_cb(bev, ctxp->user_ref);
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
