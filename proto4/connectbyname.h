/*
connectbyname.h

Interface for connectbyname
*/

struct cbn_context
{
	struct event_base *event_base;
	struct evdns_base *evdns_base;
};

struct bufferevent;
typedef void (*cbn_callback_T)(struct bufferevent *bev, void *ref);

int cbn_init(struct cbn_context *cbn_ctx, struct event_base *event_base);
void cbn_clean(struct cbn_context *cbn_ctx);

int connectbyname(struct cbn_context *cbn_ctx,
	const char *hostname, const char *servname, int *fdp);

int connectbyname_asyn(struct cbn_context *cbn_ctx,
	const char *hostname, const char *servname,
	cbn_callback_T user_cb, void *user_ref, void **refp);

void connectbyname_free(void *ref);
