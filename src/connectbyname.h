/*
 * connecbyname.h - API for connecting with services over IP networks by name
 *
 * Copyright (c) 2017, NLnet Labs. All rights reserved.
 * 
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef CONNECTBYNAME_H
#define CONNECTBYNAME_H
#include <sys/socket.h>

# ifdef __cplusplus
extern "C" {
# endif

typedef enum cbn_policy_setting {
	cbn_inherit       = 0,
	cbn_off           = 1,
	cbn_on            = 2,

	/* Both cbn_strict and cbn_opportunistic will be considered cbn_on for
	 * settings where cbn_strict and cbn_opportunistic have no meaning.
	 */
	cbn_strict        = 2,
	cbn_opportunistic = 3
} cbn_policy_setting;


struct cbn_policy {
	/** Default values from which to inherit */
	struct cbn_profile *extends;

	/** Happy Eyeballs (i.e. headstart for IPv6, default cbn_on) */
	cbn_policy_setting  happy_eyeballs		: 2;

	/** Use TLS (default cbn_opportunistic) */
	cbn_policy_setting  tls				: 2;

	/**
	 * Use DNSSEC (default cbn_opportunistic)
	 *
	 * cbn_off           = Do not do DNSSEC
	 * cbn_opportunistic = Try DNSSEC, but accept BOGUS answers too
	 * cbn_struct        = Answers must have SECURE or INSECURE
	 *                     DNSSEC status
	 */
	cbn_policy_setting  dnssec			: 2;

	/**
	 * Use DANE (default cbn_opportunistic)
	 *
	 * cbn_off           = Do not do DANE
	 * cbn_opportunistic = On BOGUS TLSA lookup, fallback to PKIX,
	 *                     but TLSA MUST be used when it is DNSSEC SECURE
	 * cbn_strict        = On BOGUS TLSA lookup, fail the conn.
	 *                     A SECURE TLSA record MUST match.
	 */
	cbn_policy_setting  dane			: 2;

	/**
	 * DNSSEC roadblock avoidance (default cbn_on)
	 *
	 * RFC8027 - Try to get DNSSEC as stub, mark upstreams with DNSSEC
	 * capabilities, fallback to full recursion if necessary.  
	 */
	cbn_policy_setting  dnssec_roadblock_avoidance	: 2;

	/**
	 * Discovery of the IPv6 Prefix Used for IPv6 Address Synthesis
	 * (default cbn_on)
	 *
	 * RFC7050 - Discover if in a NAT64/DNS64 environment, discover
	 * what prefix is used, and synthesize self so DNSSEC answers can
	 * be validated.
	 */
	cbn_policy_setting  dnssec_dns64_discovery	: 2;

	/** * Accept only DNSSEC SECURE status answers (default cbn_off) */
	cbn_policy_setting  dnssec_secure_only		: 2;

	/**
	 * Accept DNSSEC Authentication Chain TLS Extension
	 * (default cbn_opportunistic)
	 *
	 * cbn_off           = Do not announce CHAIN extension support
	 * cbn_opportunistic = Announce support and use when offered.
	 * cbn_strict        = The remote end MUST authenticate with the
	 *                     DNSSEC Authentication Chain TLS Extension
	 */
	cbn_policy_setting  tls_dnssec_chain_extension	: 2;

	int           _future_cbn_policy_settings	: 16;
	int           _future_cbn_policy_settings2	: 32;
	unsigned char _future_cbn_policy_data_settings[48];
};

#define CBN_HAPPY_EYEBALLS_OFF				(1 <<  0)
#define CBN_HAPPY_EYEBALLS_ON				(2 <<  0)

#define CBN_TLS_OFF					(1 <<  2) 
#define CBN_TLS_ON					(2 <<  2)
#define CBN_TLS_STRICT					(2 <<  2)
#define CBN_TLS_OPPORTUNISTIC				(3 <<  2)

#define CBN_DNSSEC_OFF					(1 <<  4) 
#define CBN_DNSSEC_ON					(2 <<  4)
#define CBN_DNSSEC_STRICT				(2 <<  4)
#define CBN_DNSSEC_OPPORTUNISTIC			(3 <<  4)

#define CBN_DANE_OFF					(1 <<  6) 
#define CBN_DANE_ON					(2 <<  6)
#define CBN_DANE_STRICT					(2 <<  6)
#define CBN_DANE_OPPORTUNISTIC				(3 <<  6)

#define CBN_DNSSEC_ROADBLOCK_AVOIDANCE_OFF		(1 <<  8) 
#define CBN_DNSSEC_ROADBLOCK_AVOIDANCE_ON		(2 <<  8)

#define CBN_DNSSEC_DNS64_DISCOVERY_OFF			(1 << 10) 
#define CBN_DNSSEC_DNS64_DISCOVERY_ON			(2 << 10)

#define CBN_DNSSEC_SECURE_ONLY_OFF			(1 << 12) 
#define CBN_DNSSEC_SECURE_ONLY_ON			(2 << 12)

#define CBN_TLS_DNSSEC_CHAIN_EXTENSION_OFF		(1 << 14) 
#define CBN_TLS_DNSSEC_CHAIN_EXTENSION_ON		(2 << 14)
#define CBN_TLS_DNSSEC_CHAIN_EXTENSION_ON		(2 << 14)
#define CBN_TLS_DNSSEC_CHAIN_EXTENSION_ON		(2 << 14)


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



typedef enum cbn_dnssec_status {
	cbn_SECURE        =  0,
	cbn_BOGUS         =  1,
	cbn_INSECURE      =  2,
	cbn_INDETERMINATE =  3
} cbn_dnssec_status;

struct cbn {
	const struct cbn_policy *policy;

	/* Underlying socket, should be initialized to -1 when a new socket is
	 * requested, otherwise the given socket is used.
	 */
	int                      socket;
	int                      error;
	const char              *last_error_msg;

	/* remote end */
	struct sockaddr_storage  address;

	int                      connected	:  1;
	int                      encrypted	:  1;
	int                      authenticated	:  1;
	cbn_dnssec_status        dnssec_status	:  2;

	int _future_cbn_data			: 27;
	int _future_cbn_data2			: 32;
};

struct cbn *cbn_init2(struct cbn *conn,
    struct cbn_policy *policy, const char *name, unsigned int settings);

static inline struct cbn *cbn_init(struct cbn *conn)
{ return cbn_init2(conn, NULL, NULL, 0); }

static inline struct cbn *cbn_new()
{ return cbn_init2(NULL, NULL, NULL, 0); }


struct cbn *connect_by_name2(
    const char *name, const char *service, struct cbn *conn);

static inline
struct cbn *connect_by_name(const char *name, const char *service)
{ return connect_by_name2(name, service, NULL); }

# ifdef __cplusplus
}
# endif
#endif
