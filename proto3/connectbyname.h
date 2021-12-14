/*
connectbyname.h

Interface for connectbyname
*/

struct cbn_context
{
	struct event_base *event_base;
	struct evdns_base *evdns_base;
};

int cbn_init(struct cbn_context *cbn_ctx, struct event_base *event_base);

int connectbyname(struct cbn_context *cbn_ctx,
	const char *hostname, const char *servname, int *fdp);

int connectbyname_asyn(struct cbn_context *cbn_ctx,
	const char *hostname, const char *servname,
	void (*user_cb)(int fd, void *ref), void *user_ref, void **refp);
