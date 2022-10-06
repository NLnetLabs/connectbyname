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
	struct event_base *event_base;
	struct event *event;
	void *cbn_ref;

	struct cbn_context cbn_ctx;
};

static void callback(struct bufferevent *bev, void *ref);
static void read_callback(struct bufferevent *bev, void *ref);
static void event_callback(struct bufferevent *bev, short what, void *ref);
static void usage(void);

int main(int argc, char *argv[])
{
	int r, s;
	FILE *f;
	char *hostname;
	void *ref;
	struct event_base *event_base;
	char buf[1024];
	struct state state;

	if (argc != 2)
		usage();

	hostname= argv[1];
	state.hostname= hostname;

	event_enable_debug_mode();
	event_base= event_base_new();
	state.event_base= event_base;
	cbn_init(&state.cbn_ctx, event_base);
	r= connectbyname_asyn(&state.cbn_ctx, hostname, "https",
		callback, &state, &ref);
	if (r)
	{
		fprintf(stderr, "connectbyname failed: %d\n", r);
		exit(1);
	}
	state.cbn_ref= ref;

	r= event_base_dispatch(event_base);
	fprintf(stderr, "event_base_dispatch returned: %d\n", r);
	abort();

	f= fdopen(s, "r+");
	if (f == NULL)
	{
		fprintf(stderr, "fdopen failed: %s\n", strerror(errno));
		exit(1);
	}
	fprintf(f, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", hostname);
	fflush(f);
	shutdown(s, SHUT_WR);
	for(;;)
	{
		r= fread(buf, 1, sizeof(buf), f);
		if (r == 0)
		{
			if (feof(f))
				break;
			fprintf(stderr, "read error: %s\n", strerror(errno));
			exit(1);
		}
		fwrite(buf, r, 1, stdout);
	}
	fclose(f);
	exit(0);
}

static void callback(struct bufferevent *bev, void *ref)
{
	struct state *statep;
	char reqline[80];

	statep= ref;

	snprintf(reqline, sizeof(reqline),
		"GET / HTTP/1.1\r\nHost: %s\r\n\r\n", statep->hostname);
	
	/* Assume write will not block */
	bufferevent_write(bev, reqline, strlen(reqline));
	bufferevent_enable(bev, EV_READ);
	bufferevent_setcb(bev, read_callback, NULL, event_callback, ref);
}

static void read_callback(struct bufferevent *bev, void *ref)
{
	int r;
	char line[1024];

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
