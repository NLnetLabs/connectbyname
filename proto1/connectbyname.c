/*
connectbyname.c

Implementation of connectbyname
*/

#include <string.h>
#include <netdb.h>
#include <unistd.h>

#include "connectbyname.h"

int cbn_init(struct cbn_context *cbn_ctx)
{
	memset(cbn_ctx, '\0', sizeof(cbn_ctx));
	return 0;
}

int connectbyname(struct cbn_context *cbn_ctx,
	const char *hostname, const char *servname, int *fdp)
{
	int r, s, saved_r;
	struct addrinfo *res, *tres;
	struct addrinfo hints;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_STREAM;

	r= getaddrinfo(hostname, servname, &hints, &res);
	if (r != 0)
		return -1;	/* XXX convert error */
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
}
