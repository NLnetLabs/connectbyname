/*
get80.c

Send a HTTP GET request to a target and print the result.
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <event2/event.h>

#include "connectbyname.h"

struct state
{
	char *hostname;
	struct event_base *event_base;
	struct event *event;
};

static void callback(int fd, void *ref);
static void read_callback(int fd, short events, void *ref);
static void usage(void);

int main(int argc, char *argv[])
{
	int r, s;
	FILE *f;
	char *hostname;
	void *ref;
	struct event_base *event_base;
	struct cbn_context cbn_ctx;
	char buf[1024];
	struct state state;

	if (argc != 2)
		usage();

	hostname= argv[1];
	state.hostname= hostname;

	event_enable_debug_mode();
	event_base= event_base_new();
	state.event_base= event_base;
	cbn_init(&cbn_ctx, event_base);
	r= connectbyname_asyn(&cbn_ctx, hostname, "http", callback, &state,
		&ref);
	if (r)
	{
		fprintf(stderr, "connectbyname failed: %d\n", r);
		exit(1);
	}

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

static void callback(int fd, void *ref)
{
	struct state *statep;
	char reqline[80];

	statep= ref;

	snprintf(reqline, sizeof(reqline),
		"GET / HTTP/1.1\r\nHost: %s\r\n\r\n", statep->hostname);
	
	/* Assume write will not block */
	write(fd, reqline, strlen(reqline));

	statep->event= event_new(statep->event_base, fd, EV_READ | EV_PERSIST,
		read_callback, statep);
	event_add(statep->event, NULL);
}

static void read_callback(int fd, short events, void *ref)
{
	int r;
	char line[1024];

	if (events != EV_READ)
	{
		fprintf(stderr, "read_callback: bad events value 0x%x\n",
			events);
		exit(1);
	}

	r= read(fd, line, sizeof(line));
	if (r == 0)
	{
		/* EOF */
		exit(0);
	}
	if (r == -1)
	{
		fprintf(stderr, "read error %s\n", strerror(errno));
		exit(1);
	}
	printf("%.*s", r, line);
}

static void usage(void)
{
	fprintf(stderr, "get80 <hostname>\n");
	exit(1);
}
