%%%
title = "Control Options For DNS Client Proxies"
abbrev = "codcp"
area = "Internet"
workgroup = "ADD"

[seriesInfo]
status = "standard"
name = "Internet-Draft"
value = "draft-homburg-codcp-00"
stream = "IETF"

date = 2022-05-02T00:00:00Z

[[author]]
initials="P.C."
surname="Homburg"
fullname="Philip Homburg"
organisation = "NLnet Labs"
  [author.address]
  email = "philip@nlnetlabs.nl"
%%%

.# Abstract

The introduction of many new transport protocols for DNS in recent years
(DoT, DoH, DoQ)
significantly increases the complexity of DNS stub
resolvers that want to support these protocols. A practical way forward
is to have a DNS client proxy in the host operating system. This allows
applications to communicate using Do53 and still get the privacy
benefit from using more secure protocols over the internet. However,
such a setup leaves the application with no control over which transport
the proxy uses. This document introduces EDNS(0) options that allow a
stub resolver to request certain transport and allow the proxy to report
capabilities and actual transports that are available.

{mainmatter}

# Definitions

Do53

: The original, plain text DNS transport as described in [@RFC1035].
Typically, UDP is used, with the DNS server listening on port 53. Sometimes,
for example, for large responses, TCP is used, also on port 53.

DoH

: DNS over HTTPS as described in [@RFC8484].

DoT

: DNS over TLS as described in [@RFC7858]

DoQ

: DNS over QUIC ([@RFC9000]) as described in [I-D.ietf-dprive-dnsoquic],
not to be confused with DNS over HTTP/3 which also uses QUIC

EDNS(0) Option

: An option as described in [@RFC6891]

h2

: This TLS ALPN identifies HTTP/2 as described in [@RFC7540]

h3

: This TLS ALPN identifies HTTP/3, which is HTTP over QUIC and
is described in I.D.ietf-quic-http (expired draft)

Interface Name

: A name that identifies a network interface as described in [@RFC3493].
In addition, an interface index converted to a decimal number is also
consider an interface name.

# Introduction

The introduction of many new transport protocols for DNS in recent years
(DoT, DoH, DoQ)
significantly increases the complexity of DNS stub
resolvers that want to support these protocols. In addition,
for short-lived applications, the overhead of setting a DoH connection
is quite high if the application only needs to send a few DNS requests.

A practical way forward
is to have a DNS client proxy in the host operating system.
A local proxy may provide some benefit to short-lived applications by
caching results. In particular if the system uses a so called 'public
DNS resolver'. In general we assume that the cache is tagged according
to the source of a reply and the transport it is received on.


This allows
applications to communicate using Do53 and still get the privacy
benefits from using more secure protocols over the internet. However,
such a setup leaves the application with no control over which transport
the proxy uses. This document introduces EDNS(0) options that allow a
stub resolver to request certain transports and allow the proxy to report
capabilities and actual transports that are available.


With respect to DNSSEC, we assume that an application that needs
DNSSEC validation, for example, for DANE validation or SSHFP, will
perform the DNSSEC validation within the application itself and does not
trust the proxy. The proxy can of course do DNSSEC validation as well.
Important however, is that an untrusted proxy cannot provide an application
with a traditional (unsigned) trust anchor.

For the transport configuration we expect three levels of details. The
first is a choice between requiring authenticated encryption, also allowing unauthenticated encryption or doing opportunistic encryption on an best effort basis. The second level is where the application also
specifies the names and/or IP addresses of upstream resolvers. The
third level is where the application also specifies which transports
(Do53, DoT, DoH, DoQ) are allowed to be used. A final transport parameter
is the outgoing interface that is to be used.

For authentication we can have a mix of PKI and DANE. Options are one of
the two and not the other, both or one of the two.

A poorly constructed DNS client proxy may forward DNS packets without
properly handling of EDNS(0) options. To detect and prevent this,
we introduce an option that limits the connection to host-local, link-local,
or site-local. The requirement on a conforming DNS client proxy is to
check where a request comes from and compare this to the option in
the request (if any). An error is returned if there is a mismatch.

In a response, the proxy reports the interface, resolver, and transport
used.

In the ideal case, the host operating system provides applications with a
secure way to access a DNSSEC trust anchor that is maintained according to
[@RFC5011]. However in situations where this is not the case, an application
can fall back to [@RFC7958]. However, for short lived processes, there is
considerable overhead in issuing to HTTP(S) requests to data.iana.org to
obtain the trust anchor XML file and the signature over the trust anchor.
For this reason, it makes sense to let the proxy cache this information.

# Key Words

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**",
"**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and
"**OPTIONAL**" in this document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174]
when, and only when, they appear in all capitals, as shown here.

# Description

This document introduces the new EDNS(0) options, and one new response code.
This first option, called PROXY CONTROL Option, specifies which transports
a proxy should use to connect to a recursive resolver.

The second option, called PROXY SCOPE Option, controls the IP address scope
of the connection between the application's stub resolver and the proxy.

Finally, the TRUST ANCHOR Option, provides the application with a DNSSEC
trust anchor signed by IANA.


# PROXY CONTROL OPTION

~~~
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   0: |                          OPTION-CODE                          |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   2: |                         OPTION-LENGTH                         |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   4: | U |UA | A | P | D |DO |                     Z                 |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   6: |A53|D53|AT |DT |AH2|DH2|AH3|DH3|AQ |DQ |         Z             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   8: |         Addr Type             |         Addr Length           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
      ~                IPv4 or IPv6-address(es)                       ~
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |  Domain Name Length           |                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
      ~                   Domain Name                                 ~
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |          SvcParams Length     |                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
      ~                 SvcParams                                     ~
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Interface Name Length     |                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
      ~                 Interface Name                                ~
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

where

{newline="true"}
OPTION-CODE

: To be decided

OPTION-LENGTH

: Lenght of this option excluding the OPTION-CODE and OPTION-LENGTH fields

U

: force the use of unencrypted communication (Do53)

UA

: require unauthenticated encryption

A

: require authenticated encryption

P

: authenticate using a PKI certificate

D

: authenticate using DANE

DO

: disallow other transports (transports that are not explicitly listed)

A53,AT,AH2,AH3,AQ

: allow respectively Do53, DoT, DoH H2, DoH H3, DoQ

D53,DT,DH2,DH3,DQ

: disallow respectively Do53, DoT, DoH H2, DoH H3, DoQ

Z

: reserved, MUST be zero when sending, MUST be ignored when received

Addr Type

: Type of addresses, IPv4 or IPv6

Addr Length

: length of the addresses in octets. Must be a multiple of 4 for IPv4 and
a multiple of 16 for IPv6

IPv4 or IPv6-address(es)

: list of IPv4 or IPv6 addresses

Domain Name Length

: length of Domain Name. Zero if there is no Domain Name

Domain Name

: domain name for authentication or resolving IP addresses

SvcParams Length

: length of SvcParams

SvcParams

: Service parameters

Interface Name Length

: length of Interface Name

Interface Name

: name of outgoing interface for transport connections

This option is designed to give control over what level of detail it
wants to specify. The first 5 flags (U, UA, A, P, and D) give generate
requirements for properties of DNS transports that are used by the
client proxy. The U flag specifies no encryption, the UA flag, at
least unauthenticated encryption and the A flag require authenticated
encryptions. With the U, UA, and A flags clear, an effort is made to
reach authenticated encryption, if that fails unauthenticated encryption
and if that fails, fall back to an unencrypted transport.
The P and D flags allow the application to require
a specific authentication mechanism (PKI or DANE). When both flags are set,
PKI and DANE are required together. If no flags are set, are least one of
the two has to succeed if authenticated encryption is required.

The next flags provide more detailed control over which transports
should be used or not. For each of 5 different transports
(Do53, DoT, DoH with ALPN h2, DoH with ALPN h3, DoQ) there is a flag
to allow (A53,AT,AH2,AH3,AQ) or disallow (D53,DT,DH2,DH3,DQ) the use of the
transport. There is space to add more transports later.

To future proof applications, there is a single flag DO, that disallows
transports that are not explicitly listed. With this flag clear,
the application allows future transports. With the flag set, the
application has to explicitly list which transports can be used.
For example, by setting only DO and AT, the application forces the
use of DoT.

Finally, an application can specify its own resolvers or rely on the
resolvers that are know to the proxy. If ADN Length and Addr Length
are both zero, then the application requests to resolvers known to
the proxy. [Note: it is unclear at the moment what to do with any
Service Parameters]

If the application specifies only an authentication-domain-name then the
proxy is expected to resolve the name to addresses. If only addresses
are specified then the proxy assumes that no name is known (though
a PKI certificate may include an address literal in the subjectAltName).
If both a name and address are specified then the proxy will use the
specified addresses and use the name for authentication.

To simplify the encoding of the option, an option with addresses will
have either IPv4 or IPv6 addresses. If the application wants to specify
both IPv4 and IPv6 address for a certain authentication-domain-name
then it has to include two options.

When present, Service Parameters specify how to connect. Otherwise it is
up to the proxy to try various possibilities.

# PROXY SCOPE OPTION

~~~
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   0: |                          OPTION-CODE                          |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   2: |                         OPTION-LENGTH                         |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   4: |                          Scope                                |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
~~~

{newline="true"}
OPTION-CODE

: To be decided

OPTION-LENGTH

: Length of this option excluding the OPTION-CODE and OPTION-LENGTH fields

Scope

: Scope of the source address of a request. Scope can have the following
values:

     Value | Scope
    -------|-------
     0     | Undefined
     1     | Host local
     2     | Link local
     3     | Site local
     4     | Global

The purpose of this option is to deal with badly implemented proxies that forward
DNS traffic without first removing any EDNS(0) options. The option requests
the DNS proxy that processes the option to report the scope of the source
address. The application can specify that the connection between the stub
resolver and the proxy should have, for example, at most host local scope.

# TRUST ANCHOR OPTION

~~~
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   0: |                          OPTION-CODE                          |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   2: |                         OPTION-LENGTH                         |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   4: |             ANCHORS-XML-LENGTH                                |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   6: ~             ANCHORS-XML                                       ~
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   4: |             ANCHORS-P7S-LENGTH                                |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   6: ~             ANCHORS-P7S                                       ~
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

where

{newline="true"}
OPTION-CODE

: To be decided

OPTION-LENGTH

: Lenght of this option excluding the OPTION-CODE and OPTION-LENGTH fields

ANCHORS-XML-LENGTH

: Length of ANCHORS-XML in network byte order

ANCHORS-XML

: Trust anchors in XML format

ANCHORS-P7S-LENGTH

: Length of ANCHORS-P7S in network byte order

ANCHORS-P7S

: Signature in p7s format

This option provides DNSSEC trust anchors as described in [@RFC7958].


# Protocol Specification

# Client Processing

A stub resolver that wishes to use the PROXY CONTROL Option includes the
option in all outgoing DNS requests that require privacy. The option
should be initialized according to the needs of the application.
In addition the PROXY SCOPE Option can be added. In requests, the Scope
field is set to largest scope that the application can accept.

If the stub resolver receives a reply without a PROXY CONTROL Option
included in the reply, then stub resolver has to assume that traffic will
have Do53 levels of privacy.  Similarly, a lack of a PROXY SCOPE Option
implies a global scope.

If the stub resolver receives a BADPROXYPOLICY error then the proxy was
unable to meet the requirements of the option(s). In the reply, the proxy
modifies the options to show what it can do.

## Probing

In cases where the stub resolver expects a local DNS proxy, or where the
stub resolver has (a limited) fall back to more private transports, or
when the security policy of the application is such that is better to fail
than send queries over Do53, the stub resolver first sends a probing
query to verify that the proxy supports the PROXY CONTROL and
PROXY SCOPE options.

This request queries "resolver.arpa". The proxy MUST implement this as a
Special Use Domain Name. The actual response is not important. The
important part is that the proxy returns PROXY CONTROL and PROXY SCOPE
options as described in this document and optionally sets
the response code to BADPROXYPOLICY specified policy.

## Trust Anchor

In the ideal case, the host operating system provides applications with a
secure way to access a DNSSEC trust anchor that is maintained according to
[@RFC5011]. However in situations where this is not the case, an application
can fall back to [@RFC7958]. However, for short lived processes, there is
considerable overhead in issuing to HTTP(S) requests to data.iana.org to
obtain the trust anchor XML file and the signature over the trust anchor.
For this reason, it makes sense to let the proxy cache this information.

If the local operating system does not provide a DNSSEC trust anchor, then
the application can ask the proxy. The stub resolver adds the TRUST ANCHOR
Option with ANCHORS-XML-LENGTH and ANCHORS-P7S-LENGTH. If the proxy
returns both an ANCHORS-XML and an ANCHORS-P7S, then the application verifies
the trust anchor using the trust anchor certificate (which needs to come
with the application).

# Server Processing

Proxies are encouraged to cache options that appear in requests under the
assumption that a stub resolver will send multiple requests. If a proxy
caches DNS responses then the proxy MUST tag cached responses with the
properties of the DNS transport. When responding to later requests,
the proxy returns a cached entry only if the parameters of the DNS transport
match what is specified in the request.

When a proxy receives a new set of requirements, the proxy compiles a list of
addresses to connect to and a list of transports to try per address.
The proxy SHOULD prefer more private transports over less private ones.

If the proxy cannot obtain a connection to a recursive resolver in a way that
matches the provided policy, then the proxy sets the BADPROXYPOLICY
response code in the reply. In addition the proxy SHOULD try to find at least
one connection to a recursive resolver. If the proxy did not find an
alternative connection to a recursive resolver (also if it didn't try) then
the proxy includes a PROXY CONTROL Option with all flags set to zero,
and with  ADN Length, Addr Length, and SvcParams Length set to zero as well.

If the proxy does have one or more alternative connections to recursive
resolvers then the proxy generates options with the properties of those
connection, with a maximum of three connections.

If the proxy finds a PROXY SCOPE Option, then it calculates the scope from
the source address. If the scope is larger then specified in the option,
then the proxy returns a BADPROXYPOLICY response code. The proxy sets the value of
Scope to the actual scope of the source address of the request.

If the request contains a TRUST ANCHOR Option, then the proxy tries to
fetch the trust anchor XML and p7s files if it does not have them already.
If fetching one or both fails then the proxy sets the corresponding
length to zero. It is not clear how long the proxy can cache this information.
[@RFC7958] Does not describe how long these documents can be cache.
A simple solution is to take the Expires header in the HTTP reply.

# Connection Between Stub Resolver And Proxy

Absent other configuration, a stub resolver that implements this standard
SHOULD connect to the proxy using Do53 and as remote address either ::1 or
127.0.0.1. In particular, the stub resolver SHOULD avoid using name
servers listed in files such as /etc/resolv.conf.

There reason for this is to simplify the integration of local DNS proxies
in existing environments. If the stub resolver ignores /etc/resolv.conf
then the proxy can use that information to connect to recursive resolvers.

If no DNS server is responding to queries sent using Do53 to ::1 and 127.0.0.1,
or if the response indicates that this standard is not supported, then
the stub resolver MAY fall back to traditional configuration methods, such
as /etc/resolv.conf. However, in that case the stub resolver MUST make
sure that doing so does not violate the policy set by the application.

# Security Considerations

# IANA Considerations

IANA has assigned the following DNS EDNS0 option codes:

     Value   Name           Status     Reference
    ------- -------------- ---------- -----------
     TBD     PROXY CONTROL  Standard   RFC xxxx
     TBD     PROXY SCOPE    Standard   RFC xxxx
     TBD     TRUST ANCHOR   Standard   RFC xxxx

  IANA has assigned the following DNS response code as an early allocation
  per [@RFC7120]:

     RCODE    Name             Description                   Reference
    -------- ---------------- ----------------------------- -----------
     TBD      BADPROXYPOLICY   Unable to conform to policy   RFC xxxx

# Acknowledgements

Many thanks to Yorgos Thessalonikefs and Willem Toorop for their feedback.

{backmatter}
