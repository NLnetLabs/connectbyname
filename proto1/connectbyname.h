/*
connectbyname.h

Interface for connectbyname
*/

struct cbn_context
{
	int cbn_dummy;
};

int cbn_init(struct cbn_context *cbn_ctx);

int connectbyname(struct cbn_context *cbn_ctx,
	const char *hostname, const char *servname, int *fdp);
