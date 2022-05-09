/*
connectbyname.h

Interface for connectbyname
*/

#include <getdns/getdns.h>
#include <ldns/ldns.h>

struct cbn_context
{
	struct event_base *event_base;
	getdns_context *getdns_ctx;
};

enum cbn_status
{
	CBN_OK,
	CBN_BAD_PORT,
	CBN_BAD_PORT_NAME,
	CBN_GETDNS_ERROR,
	CBN_GETDNS_REPSTATUS,
	CBN_A_AAAA_TIMEOUT,
	CBN_HOSTNAME_TOO_LONG,
	CBN_ERROR_CALLBACK,
	CBN_LDNS_ERROR,
	CBN_LDNS_RESULT,
	CBN_SSL_ERROR,
	CBN_TLSA_MISMATCH,
	CBN_DANE_TIMEOUT,
	CBN_PKIX_DID_NOT_VALIDATE
};

struct cbn_error
{
	enum cbn_status status;
	const char *msg;
	const char *file;
	int line;
	const char *func;
	union
	{
		getdns_callback_type_t callback_type;
		getdns_return_t getdns_result;
		int getdns_repstatus;
		ldns_status ldns_status;
	} u;
};

#define SET_ERROR_GENERIC(errp, error_status)		\
	(errp)->status= error_status,			\
	(errp)->file= __FILE__,				\
	(errp)->line= __LINE__,				\
	(errp)->func= __func__
#define SET_ERROR_CALLBACK(errp, callback_type) 	\
	SET_ERROR_GENERIC(errp, CBN_ERROR_CALLBACK),	\
	(errp)->u.callback_type= callback_type
#define SET_ERROR_GETDNS(errp, msgstr, r)		\
	SET_ERROR_GENERIC(errp, CBN_GETDNS_ERROR),	\
	(errp)->msg= msgstr,				\
	(errp)->u.getdns_result= r
#define SET_ERROR_GETDNS_REPSTATUS(errp, msgstr, r)	\
	SET_ERROR_GENERIC(errp, CBN_GETDNS_REPSTATUS),	\
	(errp)->msg= msgstr,				\
	(errp)->u.getdns_repstatus= r
#define SET_ERROR_A_AAAA_TIMEOUT(errp)			\
	SET_ERROR_GENERIC(errp, CBN_A_AAAA_TIMEOUT)
#define SET_ERROR_LDNS(errp, msgstr)			\
	SET_ERROR_GENERIC(errp, CBN_LDNS_ERROR),	\
	(errp)->msg= msgstr
#define SET_ERROR_LDNS_RESULT(errp, msgstr, r)		\
	SET_ERROR_GENERIC(errp, CBN_LDNS_RESULT),	\
	(errp)->msg= msgstr,				\
	(errp)->u.ldns_status= r
#define SET_ERROR_SSL(errp, msgstr)			\
	SET_ERROR_GENERIC(errp, CBN_SSL_ERROR),		\
	(errp)->msg= msgstr
#define SET_ERROR_TLSA_MISMATCH(errp)			\
	SET_ERROR_GENERIC(errp, CBN_TLSA_MISMATCH)
#define SET_ERROR_DANE_TIMEOUT(errp)			\
	SET_ERROR_GENERIC(errp, CBN_DANE_TIMEOUT)
#define SET_ERROR_PKIX_DID_NOT_VALIDATE(errp)		\
	SET_ERROR_GENERIC(errp, CBN_PKIX_DID_NOT_VALIDATE)

struct bufferevent;
typedef void (*cbn_callback_T)(struct bufferevent *bev, void *ref);
typedef void (*cbn_callback_error_T)(struct cbn_error *error, void *ref);

int cbn_init(struct cbn_context *cbn_ctx, struct event_base *event_base);
void cbn_clean(struct cbn_context *cbn_ctx);

int connectbyname(struct cbn_context *cbn_ctx,
	const char *hostname, const char *servname, int *fdp);

int connectbyname_asyn(struct cbn_context *cbn_ctx,
	const char *hostname, const char *servname,
	cbn_callback_T user_cb, cbn_callback_error_T error_cb,
	void *user_ref, void **refp);

void connectbyname_free(void *ref);
