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

#include <ldns/ldns.h>

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
	int tls_completed;
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
	getdns_transaction_t trans_id_dane;
	struct addrlist alist[MAXADDRS];
	unsigned naddrs;
	struct addrlist *mlist[MAXADDRS];

	/* Completed tls connections are stored here */
	unsigned ntls;
	struct bufferevent *tls_bev[MAXADDRS];

	/* If IPv4 address arrive first, we wait a bit for the IPv6 addresses
	 * to arrive. If the time expires, we start connecting to the IPv4
	 * addresses.
	 */
	struct event *ipv6_to_event;
	struct timespec ipv6_timeout;

	/* Event for connect timeout */
	struct event *connect_to_event;

	SSL_CTX *tls_ctx;

	/* The DANE module checks TLS connections one by one. */
	int dane_status;
	ldns_rr_list *dane_rr_list;
	struct bufferevent *dane_tls_bev;

	/* Record if we passed a connection to the user. True if we passed
	 * a connection to the user. False if the user never got anything 
	 * or asked for more.
	 */
	int user_busy;

	struct cbn_context *base;
};

#define STATE_INITIAL			0
#define STATE_DNS			1
#define STATE_DNS_IPV4_CONNECTING	2
#define STATE_DNS_IPV6_WAITING		3
#define STATE_DNS_IPV6_CONNECTING	4
#define STATE_CONNECTING		5

#define DANE_UNKNOWN			0
#define DANE_NO				1	/* No TLSA records */
#define DANE_PRESENT			2	/* TLSA record(s) present */

static void dns_callback(getdns_context *context,
	getdns_callback_type_t callback_type,
	getdns_dict *response,
	void *userarg,
	getdns_transaction_t transaction_id);
static void dane_callback(getdns_context *context,
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
static struct bufferevent *tls_get(struct work_ctx *ctxp);
static void dane_check(struct work_ctx *ctxp);
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
	int r, flags;
	getdns_return_t gdns_r;
	unsigned long port_ul;
	char *next;
	struct servent *se;
	struct work_ctx *work_ctx;
	getdns_dict *extensions;
	char danename[256];

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
	work_ctx->dane_status= DANE_UNKNOWN;

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

	extensions = getdns_dict_create();
	gdns_r = getdns_dict_set_int(extensions, "dnssec_return_status",
		GETDNS_EXTENSION_TRUE);
	if (gdns_r != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr, "getdns_dict_set_int failed\n");
		return -1;
	}
#if 1
	gdns_r = getdns_dict_set_int(extensions, "dnssec_return_validation_chain",
		GETDNS_EXTENSION_TRUE);
#endif

	r= snprintf(danename, sizeof(danename), "_%u._tcp.%s",
		ntohs(port_ul), hostname);
	if (r >= sizeof(danename))
	{
		fprintf(stderr, "DANE name too big for buffer\n");
		return -1;
	}
	gdns_r= getdns_general(cbn_ctx->getdns_ctx,
		danename, GETDNS_RRTYPE_TLSA,
		extensions, work_ctx, &work_ctx->trans_id_dane,
		dane_callback);
	getdns_dict_destroy(extensions);
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
	printf("len %lu\n", len);
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
			(int)addr_type->size, addr_type->data);

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
			alist->tls_completed= 0;

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
			alist->tls_completed= 0;

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
			fprintf(stderr, "dns_callback: now %ld.%09ld\n",
				timeout.tv_sec, timeout.tv_nsec);
			timeout.tv_nsec += TIMEOUT_NS % NS_PER_SEC;
			timeout.tv_sec += TIMEOUT_NS / NS_PER_SEC;
			fprintf(stderr, "dns_callback: timeout %ld.%09ld\n",
				timeout.tv_sec, timeout.tv_nsec);
			if (timeout.tv_nsec >= NS_PER_SEC)
			{
				timeout.tv_nsec -= NS_PER_SEC;
				timeout.tv_sec++;
			}
			fprintf(stderr, "dns_callback: timeout %ld.%09ld\n",
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

static struct bufferevent *tls_get(struct work_ctx *ctxp)
{
	struct bufferevent *bev;

	if (ctxp->ntls > 0)
	{
		/* We got more tls connection avaible */
		ctxp->ntls--;
		bev= ctxp->tls_bev[ctxp->ntls];
		ctxp->tls_bev[ctxp->ntls]= NULL;

		return bev;
	}

	/* Restart connect */
	do_connect(ctxp);
	return NULL;
}

static void dane_callback(getdns_context *context,
	getdns_callback_type_t callback_type,
	getdns_dict *response,
	void *userarg,
	getdns_transaction_t transaction_id)
{
	int b, i, j, status, type;
	size_t answers_len, replies_tree_len;
	uint32_t u32;
	struct work_ctx *ctxp;
	getdns_return_t gdns_r;
	ldns_status ldns_r;
	getdns_dict *answer, *reply;
	getdns_list *answers, *replies_tree;
	ldns_rr_list *rr_list;
	ldns_rr *rr;
	ldns_rdf *rdf;
	getdns_bindata *bindata;
	struct bufferevent *bev;

	ctxp= userarg;
	if (callback_type != GETDNS_CALLBACK_COMPLETE)
	{
		/* Should handle DNS errors */
		fprintf(stderr, "dane_callback, callback_type %d\n",
			callback_type);
		goto cleanup;
	}

#if 0
	printf("dane_callback: got\n");
	printf("%s\n", getdns_pretty_print_dict(response));
	fflush(stdout);
#endif

	rr_list= NULL;

	gdns_r= getdns_dict_get_list(response, "replies_tree", &replies_tree);
	if (gdns_r != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr,
		"dane_callback: nothing for 'replies_tree': %d\n",
			gdns_r);
		goto cleanup;
	}
	gdns_r= getdns_list_get_length(replies_tree, &replies_tree_len);
	if (gdns_r != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr,
		"dane_callback: no length of 'replies_tree': %d\n",
			gdns_r);
		goto cleanup;
	}
	for (i= 0; i<replies_tree_len; i++)
	{
		gdns_r= getdns_list_get_dict(replies_tree, i, &reply);
		if (gdns_r != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
			"dane_callback: nothing for 'replies_tree[%d]': %d\n",
				i, gdns_r);
			goto cleanup;
		}
		gdns_r= getdns_dict_get_list(reply, "answer", &answers);
		if (gdns_r != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
		"dane_callback: nothing for 'replies_tree[%d].answer': %d\n",
				i, gdns_r);
			goto cleanup;
		}
		gdns_r= getdns_list_get_length(answers, &answers_len);
		if (gdns_r != GETDNS_RETURN_GOOD)
		{
			fprintf(stderr,
			"dane_callback: no length of 'answers': %d\n",
				gdns_r);
			goto cleanup;
		}
		for (j= 0; j<answers_len; j++)
		{
			gdns_r= getdns_list_get_dict(answers, j, &answer);
			if (gdns_r != GETDNS_RETURN_GOOD)
			{
				fprintf(stderr,
	"dane_callback: nothing for 'replies_tree[%d].answer[%d]': %d\n",
					i, j, gdns_r);
				goto cleanup;
			}
			gdns_r= getdns_dict_get_int(answer, "type", &type);
			if (gdns_r != GETDNS_RETURN_GOOD)
			{
				fprintf(stderr,
	"dane_callback: nothing for 'replies_tree[%d].answer[%d].type': %d\n",
					i, j, gdns_r);
				goto cleanup;
			}
			if (type != GETDNS_RRTYPE_TLSA)
				continue;
#if 0
	fprintf(stderr, "dane_callback: got\n");
	fprintf(stderr, "%s\n", getdns_pretty_print_dict(response));
#endif
			if (!rr_list)
			{
				rr_list= ldns_rr_list_new();
			}
			rr= ldns_rr_new_frm_type(LDNS_RR_TYPE_TLSA);

			gdns_r= getdns_dict_get_int(answer,
				"/rdata/certificate_usage", &u32);
			if (gdns_r != GETDNS_RETURN_GOOD)
			{
				fprintf(stderr,
"dane_callback: nothing for 'replies_tree[%d].answer[%d].rdata.certificate_usage': %d\n",
					i, j, gdns_r);
				goto cleanup;
			}
			rdf= ldns_native2rdf_int8(LDNS_RDF_TYPE_UNKNOWN, u32);
			if (!rdf)
			{
				fprintf(stderr,
			"dane_callback: ldns_native2rdf_int8 failed\n");
				goto cleanup;
			}
			ldns_rr_set_rdf(rr, rdf, 0);

			gdns_r= getdns_dict_get_int(answer,
				"/rdata/selector", &u32);
			if (gdns_r != GETDNS_RETURN_GOOD)
			{
				fprintf(stderr,
"dane_callback: nothing for 'replies_tree[%d].answer[%d].rdata.selector': %d\n",
					i, j, gdns_r);
				goto cleanup;
			}
			rdf= ldns_native2rdf_int8(LDNS_RDF_TYPE_UNKNOWN, u32);
			if (!rdf)
			{
				fprintf(stderr,
			"dane_callback: ldns_native2rdf_int8 failed\n");
				goto cleanup;
			}
			ldns_rr_set_rdf(rr, rdf, 1);

			gdns_r= getdns_dict_get_int(answer,
				"/rdata/matching_type", &u32);
			if (gdns_r != GETDNS_RETURN_GOOD)
			{
				fprintf(stderr,
"dane_callback: nothing for 'replies_tree[%d].answer[%d].rdata.matching_type': %d\n",
					i, j, gdns_r);
				goto cleanup;
			}
			rdf= ldns_native2rdf_int8(LDNS_RDF_TYPE_UNKNOWN, u32);
			if (!rdf)
			{
				fprintf(stderr,
			"dane_callback: ldns_native2rdf_int8 failed\n");
				goto cleanup;
			}
			ldns_rr_set_rdf(rr, rdf, 2);

			gdns_r= getdns_dict_get_bindata(answer,
				"/rdata/certificate_association_data",
				&bindata);
			if (gdns_r != GETDNS_RETURN_GOOD)
			{
				fprintf(stderr,
"dane_callback: nothing for 'replies_tree[%d].answer[%d].rdata.certificate_association_data': %d\n",
					i, j, gdns_r);
				goto cleanup;
			}
			rdf= ldns_rdf_new_frm_data(LDNS_RDF_TYPE_UNKNOWN,
				bindata->size, bindata->data);
			if (!rdf)
			{
				fprintf(stderr,
			"dane_callback: ldns_rdf_new_frm_data failed\n");
				goto cleanup;
			}
			ldns_rr_set_rdf(rr, rdf, 3);

			b= ldns_rr_list_push_rr(rr_list, rr); rr= NULL;
			if (!b)
			{
				fprintf(stderr,
			"dane_callback: ldns_rr_list_push_rr failed\n");
				goto cleanup;
			}
		}
	}

	if (rr_list)
	{
		ctxp->dane_rr_list= rr_list;
		ctxp->dane_status= DANE_PRESENT;
		rr_list= NULL;
	}
	else
	{
		/* No TLSA record */
		ctxp->dane_status= DANE_NO;
		goto cleanup;
	}

	gdns_r= getdns_dict_get_int(response, "status",
		&status);
	if (gdns_r != GETDNS_RETURN_GOOD)
	{
		fprintf(stderr,
		"dane_callback: nothing for 'status': %d\n",
			gdns_r);
		goto cleanup;
	}

	switch(status)
	{
	case GETDNS_RESPSTATUS_GOOD:
		break;
	default:
		fprintf(stderr, "dane_callback: unknown status %d\n", status);
		goto cleanup;
	}

	while(ctxp->dane_tls_bev)
	{
		dane_check(ctxp);
		assert(!ctxp->dane_tls_bev);

		if (ctxp->user_busy)
			break;	/* No need for me connections */

		fprintf(stderr, "dane_callback: calling tls_get\n");
		ctxp->dane_tls_bev= tls_get(ctxp);
	}

cleanup:
	getdns_dict_destroy(response);
	response= NULL;
}

static void dane_check(struct work_ctx *ctxp)
{
	ldns_status ldns_r;
	SSL *ssl;
	X509* cert;
	X509_STORE *store;
	struct bufferevent *bev;

	if (ctxp->user_busy)
	{
		/* We already passed a connection to the user. Wait until
		 * the user asks for more.
		 */
		fprintf(stderr, "dane_check: user already busy\n");
		return;
	}

	switch (ctxp->dane_status)
	{
	case DANE_UNKNOWN:
		/* No DANE record yet. */
		return;

	case DANE_PRESENT:
		/* We have a DANE record. Check. */
		break;

	default:
		fprintf(stderr, "dane_check: unknown dane_status %d\n",
			ctxp->dane_status);
		abort();
	}

	bev= ctxp->dane_tls_bev;
	ctxp->dane_tls_bev= NULL;

	ssl= bufferevent_openssl_get_ssl(bev);
	fprintf(stderr, "dane_check: ssl = %p\n", ssl);

	cert = SSL_get_peer_certificate(ssl);
	if (!cert) {
		fprintf(stderr,
		"dane_check: SSL_get_peer_certificate failed\n");
		goto cleanup;
	}

	store= X509_STORE_new();
	if (X509_STORE_load_locations(store, NULL,
		"/usr/lib/ssl/certs") != 1) {
		fprintf(stderr,
		"dane_check: X509_STORE_load_locations failed\n");
		goto cleanup;
	}
	ldns_r= ldns_dane_verify(ctxp->dane_rr_list, cert, NULL, store);

	fprintf(stderr, "ldns_r == %d\n", ldns_r);

	switch(ldns_r)
	{
	case LDNS_STATUS_OK:
		/* Record the fact that we passed a bev to the user. */
		ctxp->user_busy= 1;
		ctxp->user_cb(bev, ctxp->user_ref);
		break;

	case LDNS_STATUS_DANE_TLSA_DID_NOT_MATCH:
		fprintf(stderr, "dane_check: should record ldns error\n");

		/* Drop the bev */
		bufferevent_free(bev);
                bev= NULL;
		
		break;
 		
	default:
		fprintf(stderr, "dane_check: unknown ldns result %d\n", ldns_r);
		abort();
	}
	
cleanup:
	fprintf(stderr, "dane_check: should do cleanup\n");
}

/* Called by TLS to tell DANE about a new TLS connection. This function
 * returns 0 if there is no space, and 1 if the connection is accepted.
 * DANE checks the connects and passes it to the user if it validates or
 * if there is no DANE record.
 */
static int dane_accept_tls_bev(struct work_ctx *ctxp, struct bufferevent *bev)
{
	fprintf(stderr, "in dane_accept_tls_bev\n");
	if (ctxp->dane_tls_bev)
		return 0;	/* Already got something. */
	ctxp->dane_tls_bev= bev;
	dane_check(ctxp);

	/* Get more connections if the one we got didn't work out */
	while(!ctxp->dane_tls_bev && !ctxp->user_busy)
	{
		fprintf(stderr, "dane_accept_tls_bev: calling tls_get\n");
		bev= tls_get(ctxp);
		if (!bev)
			break;
		ctxp->dane_tls_bev= bev; bev= NULL;
		dane_check(ctxp);
	}

	return 1;
}

static void timeout_callback(evutil_socket_t fd, short events, void *ref)
{
	struct work_ctx *ctxp;
	struct timespec now;
	struct timeval timeout;

	ctxp= ref;
	clock_gettime(CLOCK_MONOTONIC, &now);
	fprintf(stderr, "timeout_callback: now %ld.%09ld\n",
		now.tv_sec, now.tv_nsec);
	fprintf(stderr, "timeout_callback: target %ld.%09ld\n",
		ctxp->ipv6_timeout.tv_sec, ctxp->ipv6_timeout.tv_nsec);

	if (now.tv_sec < ctxp->ipv6_timeout.tv_sec ||
		(now.tv_sec == ctxp->ipv6_timeout.tv_sec &&
		now.tv_nsec < ctxp->ipv6_timeout.tv_nsec))
	{
		/* Set timer */
		timeout.tv_sec= ctxp->ipv6_timeout.tv_sec - now.tv_sec;
		timeout.tv_usec= (ctxp->ipv6_timeout.tv_nsec - now.tv_nsec)/
			1000 + 1;

		fprintf(stderr, "timeout %ld.%06ld\n",
			timeout.tv_sec, timeout.tv_usec);
		if (timeout.tv_usec < 0)
		{
			timeout.tv_usec += US_PER_SEC;
			timeout.tv_sec--;
		}
		fprintf(stderr, "timeout %ld.%06ld\n",
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
	fprintf(stderr, "connect_callback: tls = %p\n", tls);

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

	/* Stop connect_to_event. We don't need more connections
	 * at this moment.
	 */
	assert(ctxp->connect_to_event);
	evtimer_del(ctxp->connect_to_event);

	/* Find bev */
	for (i= 0, ap= ctxp->alist; i<ctxp->naddrs; i++, ap++)
	{
		if (ap->bev == bev)
			break;
	}

	if (i >= ctxp->naddrs)
	{
		/* Not found. Weird */
		fprintf(stderr,
			"event_callback: bev not found, weird\n");
		return;
	}

	/* Found the right event */
	ap->bev= NULL;
	ap->socket= -1;
	ap->tls_completed= 1;

	/* Tell DANE */
	if (!dane_accept_tls_bev(ctxp, bev))
	{
		/* Dane did not accept this connection */
		ctxp->tls_bev[ctxp->ntls]= bev; bev= NULL;
		ctxp->ntls++;
	}

	return;

#if 0
	fprintf(stderr, "event_callback: should handle DANE\n");
	abort();

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
#endif
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

	fprintf(stderr, "in do_connect\n");

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
		if (ap->tls_completed)
			continue;	/* This address is done */

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
