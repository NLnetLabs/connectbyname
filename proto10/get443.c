/*
get443.c

Send a HTTP GET request to a target and print the result.
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <event2/event.h>
#include <event2/bufferevent.h>

#include "connectbyname.h"

struct state
{
	char *hostname;
	char *hostname_port;
	char *path;
	struct event_base *event_base;
	struct event *event;
	void *cbn_ref;

	struct cbn_context cbn_ctx;
};

static void parse_url(char *url, char **schemep,  char **host_portp,
	char **hostnamep, char **portp, char **pathp);
static void callback(struct bufferevent *bev, void *ref);
static void error_cb(struct cbn_error *error, void *ref);
static void read_callback(struct bufferevent *bev, void *ref);
static void event_callback(struct bufferevent *bev, short what, void *ref);
static void usage(void);

int main(int argc, char *argv[])
{
	int r, s;
	FILE *f;
	char *scheme, *hostname_port, *hostname, *port_str, *path;
	void *ref;
	struct event_base *event_base;
	struct addrinfo *ai, *tmp_ai;
	const char *addr_str;
	struct addrinfo hints;
	char buf[1024];
	struct state state;
	struct cbnp_resolver resolver1, resolver2;
	struct cbn_policy policy;

	if (argc != 2)
		usage();

	parse_url(argv[1], &scheme, &hostname_port, &hostname, &port_str,
		&path);

	state.hostname= hostname;
	state.hostname_port= hostname_port;
	state.path= path;

	event_enable_debug_mode();
	event_base= event_base_new();
	state.event_base= event_base;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_DGRAM;	/* Doesn't matter what we pick,
					 * we want one address.
					 */
	addr_str = "2001:4860:4860::8888";
	// addr_str = "2a10:3781:2413:1:2a0:c9ff:fe9f:16bd";
	// addr_str = "2606:4700::6812:152c";
	getaddrinfo(addr_str, "domain", &hints, &ai);
	// getaddrinfo("8.8.8.8", "domain", &hints, &ai);

	resolver1.settings= 
		// CBN_UNENCRYPTED |
		// CBN_UNAUTHENTICATED_ENCRYPTION |
		// CBN_AUTHENTICATED_ENCRYPTION |
		// CBN_PKIX_AUTH_REQUIRED |
		// CBN_DANE_AUTH_REQUIRED |
		CBN_DEFAULT_DISALLOW_OTHER_TRANSPORTS |
		CBN_ALLOW_DO53 |
		// CBN_DISALLOW_DO53 |
		CBN_ALLOW_DOT |
		// CBN_DISALLOW_DOT |
		CBN_ALLOW_DOH2 |
		// CBN_DISALLOW_DOH2 |
		CBN_ALLOW_DOH3 |
		// CBN_DISALLOW_DOH3 |
		CBN_ALLOW_DOQ; // |
		// CBN_DISALLOW_DOQ;
	resolver1.domain_name= "dns.google";
	resolver1.domain_name= NULL;
	for (resolver1.naddrs= 0, tmp_ai= ai;
		resolver1.naddrs < CBNPR_MAX_ADDRS && tmp_ai != NULL;
		resolver1.naddrs++, tmp_ai= tmp_ai->ai_next)
	{
		assert(tmp_ai->ai_addrlen <= sizeof(resolver1.addrs[0]));
		memcpy(&resolver1.addrs[resolver1.naddrs],
			tmp_ai->ai_addr, tmp_ai->ai_addrlen);
	}
	resolver1.svcparams= "port=4242 no-default-alpn alpn=h2 mandatory=no-default-alpn,alpn";
	resolver1.svcparams= "no-default-alpn alpn=h2 mandatory=no-default-alpn,alpn";
	resolver1.svcparams= NULL;
	resolver1.interface= "foo";
	resolver1.interface= NULL;

	addr_str = "2001:4860:4860::8888";
	// addr_str = "2a10:3781:2413:1:2a0:c9ff:fe9f:16bd";
	getaddrinfo(addr_str, "domain", &hints, &ai);
	// getaddrinfo("8.8.8.8", "domain", &hints, &ai);

	resolver2.settings= 
		// CBN_UNENCRYPTED |
		// CBN_UNAUTHENTICATED_ENCRYPTION |
		// CBN_AUTHENTICATED_ENCRYPTION |
		// CBN_PKIX_AUTH_REQUIRED |
		// CBN_DANE_AUTH_REQUIRED |
		CBN_DEFAULT_DISALLOW_OTHER_TRANSPORTS |
		CBN_ALLOW_DO53 |
		// CBN_DISALLOW_DO53 |
		CBN_ALLOW_DOT |
		// CBN_DISALLOW_DOT |
		CBN_ALLOW_DOH2 |
		// CBN_DISALLOW_DOH2 |
		CBN_ALLOW_DOH3 |
		// CBN_DISALLOW_DOH3 |
		CBN_ALLOW_DOQ; // |
		// CBN_DISALLOW_DOQ;
	resolver2.domain_name= "dns.google";
	resolver2.domain_name= NULL;
	for (resolver2.naddrs= 0, tmp_ai= ai;
		resolver2.naddrs < CBNPR_MAX_ADDRS && tmp_ai != NULL;
		resolver2.naddrs++, tmp_ai= tmp_ai->ai_next)
	{
		assert(tmp_ai->ai_addrlen <= sizeof(resolver2.addrs[0]));
		memcpy(&resolver2.addrs[resolver2.naddrs],
			tmp_ai->ai_addr, tmp_ai->ai_addrlen);
	}
	resolver2.svcparams= "port=4242 no-default-alpn alpn=h2 mandatory=no-default-alpn,alpn";
	resolver2.svcparams= "no-default-alpn alpn=h2 mandatory=no-default-alpn,alpn";
	resolver2.svcparams= NULL;
	resolver2.interface= "foo";
	resolver2.interface= NULL;

	cbn_policy_init2(&policy, "name", 0);
	cbn_policy_set_scheme(&policy, scheme);
	cbn_policy_add_resolver(&policy, &resolver1);
	cbn_policy_add_resolver(&policy, &resolver2);

	freeaddrinfo(ai);

	/* If port_str == NULL, try to compute port from scheme */
	if (port_str == NULL)
	{
		if (strcmp(scheme, "http") == 0 ||
			strcmp(scheme, "https") == 0)
		{
			port_str= strdup(scheme);
		}
		else
		{
			fprintf(stderr, "no default port for scheme %s\n",
				scheme);
			exit(1);
		}
	}

	cbn_init2(&state.cbn_ctx, &policy, "name", 0, event_base);
	r= connectbyname_asyn(&state.cbn_ctx, hostname, port_str,
		callback, error_cb, &state, &ref);
	if (r)
	{
		fprintf(stderr, "connectbyname failed: %d\n", r);
		exit(1);
	}
	fprintf(stderr, "main: &state: %p, ref %p\n", &state, ref);
	state.cbn_ref= ref;

	r= event_base_dispatch(event_base);
	fprintf(stderr, "event_base_dispatch returned: %d\n", r);
	abort();

	exit(0);
}

static void parse_url(char *url, char **schemep,  char **hostname_portp,
	char **hostnamep, char **portp, char **pathp)
{
	size_t len;
	char *p1, *p2;
	char *scheme, *hostname_port, *hostname, *port, *path;

	/* We need a scheme. First reject URLs that start with a slash */
	if (url[0] == '/')
	{
		fprintf(stderr, "parse_url: scheme required in URL %s\n",
			url);
		exit(1);
	}
	p1= strchr(url, ':');
	if (p1 == NULL || p1[1] != '/' || p1[2] != '/')
	{
		fprintf(stderr, "parse_url: scheme required in URL %s\n",
			url);
		exit(1);
	}
	len= p1-url;
	scheme= malloc(len+1);
	memcpy(scheme, url, len);
	scheme[len]= '\0';
	p1 += 3;
	
	fprintf(stderr, "parse_url: scheme %s\n", scheme);

	/* Hostname and port */
	p2= strchr(p1, '/');
	if (p2 == NULL)
	{
		hostname_port= strdup(p1);
	}
	else
	{
		len= p2-p1;
		hostname_port= malloc(len+1);
		memcpy(hostname_port, p1, len);
		hostname_port[len]= '\0';
	}

	fprintf(stderr, "parse_url: hostname and port %s\n", hostname_port);

	/* Hostname could be an IPv6 literal. Check that first */
	if (hostname_port[0] == '[')
	{
		p1= strchr(hostname_port, ']');
		if (p1 == NULL)
		{
			fprintf(stderr, "parse_url: bad IPv6 literal in %s\n",
				hostname_port);
			abort();
		}
		len= p1-(hostname_port+1);
		hostname= malloc(len+1);
		memcpy(hostname, hostname_port+1, len);
		hostname[len]= '\0';
		
		p1++;

		if (p1[0] == ':')
			; /* Okay, start of port */
		else if (p1[0] == '\0')
		{
			/* No port, set p1 to NULL, to be consistent with 
			 * strchr(..., ':')
			 */
			p1= NULL;
		}
		else
		{
			fprintf(stderr, "parse_url: bad port part %s\n", p1);
		}
	}
	else
	{
		p1= strchr(hostname_port, ':');
		if (p1 == NULL)
		{
			hostname= strdup(hostname_port);
		}
		else
		{
			len= p1-hostname_port;
			hostname= malloc(len+1);
			memcpy(hostname, hostname_port, len);
			hostname[len]= '\0';
		}
	}

	fprintf(stderr, "parse_url: hostname %s\n", hostname);

	if (!p1)
	{
		port= NULL;
	}
	else
		port= strdup(p1+1);

	fprintf(stderr, "parse_url: port %s\n", port);

	/* Path */
	if (p2)
	{
		path= strdup(p2);
	}
	else
		path= NULL;

	fprintf(stderr, "parse_url: path %s\n", path);

	*schemep= scheme;
	*hostname_portp= hostname_port;
	*hostnamep= hostname;
	*portp= port;
	*pathp= path;
}

static void callback(struct bufferevent *bev, void *ref)
{
	struct state *statep;
	char reqline[80];

	statep= ref;

	snprintf(reqline, sizeof(reqline),
		"GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		statep->path ? statep->path : "/",
		statep->hostname_port);

	fprintf(stderr, "callback: sending request %s\n", reqline);
	
	/* Assume write will not block */
	bufferevent_write(bev, reqline, strlen(reqline));
	bufferevent_enable(bev, EV_READ);
	bufferevent_setcb(bev, read_callback, NULL, event_callback, ref);
}

static void error_cb(struct cbn_error *error, void *ref)
{
	fprintf(stderr, "Got error: %d (%s) from %s, %s, %d\n", error->status,
		error->msg, error->func, error->file, error->line);
	exit(1);
}

static void read_callback(struct bufferevent *bev, void *ref)
{
	int r;
	char line[1024];

	printf("\n\nin read_callback\n\n");

	for (;;)
	{
		r= bufferevent_read(bev, line, sizeof(line));
		if (r == 0)
			break;
		if (r == -1)
		{
			fprintf(stderr, "read error %s\n", strerror(errno));
			exit(1);
		}
		printf("%.*s", r, line);
	}
}

static void event_callback(struct bufferevent *bev, short what, void *ref)
{
	struct state *statep;

	statep= ref;

	if ((what & (BEV_EVENT_READING|BEV_EVENT_EOF)) ==
		(BEV_EVENT_READING|BEV_EVENT_EOF))
	{
		/* EOF */

		/* Free bufferevent */
		bufferevent_free(bev);
		bev= NULL;

		fprintf(stderr, "event_callback: statep: %p, ref %p\n",
			statep, statep->cbn_ref);
		
		/* Connectbyname call */
		connectbyname_free(statep->cbn_ref);
		statep->cbn_ref= NULL;

		/* Connectbyname context */
		cbn_clean(&statep->cbn_ctx);

		/* event base */
		event_base_free(statep->event_base);
		statep->event_base= NULL;

		exit(0);
	}
	fprintf(stderr, "event_callback: what %d\n", what);
}

static void usage(void)
{
	fprintf(stderr, "get80 <hostname>\n");
	exit(1);
}
