/*
connectbyname.h

Interface for connectbyname
*/

#include <getdns/getdns.h>
#include <ldns/ldns.h>

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

#define CBNPR_MAX_ADDRS	3

/* Policy for connecting upstream resolver */
struct cbnp_resolver
{
	unsigned int settings;
	char *domain_name;
	int naddrs;
	struct sockaddr_storage addrs[CBNPR_MAX_ADDRS];
	char *svcparams;
	char *interface;
};

#define CBN_UNENCRYPTED			(1 << 0)
#define CBN_UNAUTHENTICATED_ENCRYPTION	(1 << 1)
#define CBN_AUTHENTICATED_ENCRYPTION	(1 << 2)
#define CBN_PKIX_AUTH_REQUIRED		(1 << 3)
#define CBN_DANE_AUTH_REQUIRED		(1 << 4)
#define CBN_DEFAULT_DISALLOW_OTHER_TRANSPORTS	(1 << 5)
#define CBN_ALLOW_DO53			(1 << 8)
#define CBN_DISALLOW_DO53		(1 << 9)
#define CBN_ALLOW_DOT			(1 << 10)
#define CBN_DISALLOW_DOT		(1 << 11)
#define CBN_ALLOW_DOH2			(1 << 12)
#define CBN_DISALLOW_DOH2		(1 << 13)
#define CBN_ALLOW_DOH3			(1 << 14)
#define CBN_DISALLOW_DOH3		(1 << 15)
#define CBN_ALLOW_DOQ			(1 << 16)
#define CBN_DISALLOW_DOQ		(1 << 17)

#define MAX_RESOLVERS	10

struct cbn_policy
{
	int resolver_count;
	struct cbnp_resolver resolver[MAX_RESOLVERS];
	char *scheme;
};

struct cbn_context
{
	struct event_base *event_base;
	getdns_context *getdns_ctx;
	struct cbn_policy policy;
};

/**
 * Initializes the cbn_policy
 * @param policy   The policy to initialize, already allocated or on the
 *                 stack.  When policy is NULL, a new cbn_policy will be
 *                 allocated.
 * @param name     The name from  which to determine what policy setting
 *                 to inherit.
 * @param settings A bitwise-orred value witth settings for the individual
 *                 settings.  Missing values will be interpreted as inherit.
 * @return The initialized cbn_policy or NULL on error.
 *         Error will occur only when memory could not be allocated.
 */
struct cbn_policy *cbn_policy_init2(
    struct cbn_policy *policy, const char *name, unsigned int settings);

/**
 * Initializes the cbn_policy to inherit from the default policy for
 * the application, and sets all cbn_policy_setting variables to cbn_inherit.
 * @param policy The policy already allocated or on the stack to initialize
 *               or NULL to allocate a new policy.
 * @return The initialized cbn_policy or NULL on error.
 *         Error will occur only when memory could not be allocated.
 */
static inline
struct cbn_policy *cbn_policy_init(struct cbn_policy *policy)
{ return cbn_policy_init2(policy, NULL, 0); }

/**
 * Allocate a new cbn_policy that inherits from the default policy for
 * the application, and sets all cbn_policy_setting variables to cbn_inherit.
 * @return The newly allocated cbn_policy or NULL on error.
 *         Error will occur only when memory could not be allocated.
 */
static inline struct cbn_policy *cbn_policy_new()
{ return cbn_policy_init2(NULL, NULL, 0); }

int cbn_policy_add_resolver(struct cbn_policy *policy,
	struct cbnp_resolver *resolver);

int cbn_init(struct cbn_context *cbn_ctx, struct event_base *event_base);
int cbn_init2(struct cbn_context *cbn_ctx, struct cbn_policy *policy,
	char *name, int flags, struct event_base *event_base);
void cbn_clean(struct cbn_context *cbn_ctx);

int connectbyname(struct cbn_context *cbn_ctx,
	const char *hostname, const char *servname, int *fdp);

int connectbyname_asyn(struct cbn_context *cbn_ctx,
	const char *hostname, const char *servname,
	cbn_callback_T user_cb, cbn_callback_error_T error_cb,
	void *user_ref, void **refp);

void connectbyname_free(void *ref);
