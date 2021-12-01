/*
get80.c

Send a HTTP GET request to a target and print the result.
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "connectbyname.h"

static void usage(void);

int main(int argc, char *argv[])
{
	int r, s;
	FILE *f;
	char *hostname;
	struct cbn_context cbn_ctx;
	char buf[1024];

	if (argc != 2)
		usage();

	hostname= argv[1];

	cbn_init(&cbn_ctx);
	r= connectbyname(&cbn_ctx, hostname, "http", &s);
	if (r)
	{
		fprintf(stderr, "connectbyname failed: %d\n", r);
		exit(1);
	}

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

static void usage(void)
{
	fprintf(stderr, "get80 <hostname>\n");
	exit(1);
}
