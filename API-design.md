# High level goals

The basic concept of 'Connect By Name' is easy to explain. In terms of the C language, a function with prototype:

```
int connectbyname(const char *hostname, const char *servname);
```

that returns a connected TCP socket.

This function can be trivially implemented with calls to 
getaddrinfo, socket, and connect.

However, we want more functionality than just the basics. Many applications
need a TLS connection instead of just a TCP socket. With TLS also comes
the need to support DANE and optionally RFC 9102 (TLS DNSSEC Chain Extension),
which is experimental.

Instead of waiting for both the DNS 'A' and 'AAAA' queries to complete and
then connecting to each address in turn, we need to implement 'Happy Eyeballs',
which uses relatively short timeouts to try IPv6 first, but fall 
back to IPv4 if that does not succeed fast enough.

At the DNS level, we need to have the option of local DNSSEC validation,
fetching a trust anchor, plain old DNS on port 53, DNS over TLS, DNS over
HTTPS. 

At the API level, we need to support event-based applications.

# Specifics of the API

We can separate the API interface from the functionality provide by the API.
The API interface design involves questions such as how to pass options
to the API and receive information about the resulting configuration.
How to deal with the various libraries that implement TLS and
how to deal with event-based applications.

Starting with

```
int connectbyname(const char *hostname, const char *servname);
```
the first thing that is obviously missing is ability to pass options to
the call. For example, getaddrinfo has a 'hints' parameter. Getdns uses
a context and an extensions dict. As a starting point we can assume a
context parameter. So we get something like this:

```
int connectbyname(context_T *context, const char *hostname,
	const char *servname);
```
Next, we have the issue of TLS. There are many TLS libraries. One option
is to define one API call per library where the user selects which one
should be provided. For example,

```
SSL *connectbynameOpenSSL(context_T *context, const char *hostname,
        const char *servname);
```
The advantage of this approach is that the client can use all functions of
the TLS library (for example, to check which ciphers are negotiated).

An alternative approach is to have a generic interface, similar to libevents
struct bufferevent. This makes the core of the API independent of the
specific TLS library that is used. For example,

```
struct bufferevent *connectbynameTLS(context_T *context,
	const char *hostname, const char *servname);
```
Note that we probably need a way to pass library specific configuration
options before the TLS connection is created and we probably need to get the
underlying TLS library object as well to perform library specific functions.
But hopefully, that is something for specialized applications and not the
common case.

Next, we have the way to make functions asynchronous. The easiest way
is to add a callback function and a client ref to the parameters and 
return an API ref that can be used, for example, to cancel the operation.
For example,

```
struct bufferevent *connectbynameTLS(context_T *context,
	const char *hostname, const char *servname, callback_T *callback,
	ref_T client_ref, ref_T *api_ref);
```
Finally, we need a way to specify orchestration. Do we want, or insist on
DANE. Do we want DoT, etc.

# Functionality

One way to model functionality is as a collection of processes. The actual
implementation has to be asynchronous. But a collection of processes is easy
to reason about.

At the heart is the Happy Eyballs process. This process receives a stream of
DNS replies and produces a stream of connected TCP sockets. Note that
the process is expected receive at most one reply to an 'A' query and one
for a 'AAAA'. Similarly, we expect that the consumer of the sockets will
initially receive one and request more if the ones already delivered don't
work out.

The TLS process uses the sockets from the Happy Eyeballs process to set up
a TLS connection. This process optionally receives a DANE reply. If
RFC 9102 is implemented then during the setup of the TLS connection,
the process receives a collection of DNS replies that need to be 
DNSSEC validated.

At the bottom we expect four types of DNS processes. These processes
receive a series of DNS requests and produce a series of DNS replies.
The most basic of these DNS processes is Do53. This is the classical,
UDP-based DNS transport with a fallback to TCP. Typical configuration is
a collection of addresses, usually obtained from /etc/resolv.conf.

Then there is DoT. The DoT is similar to Do53, in that configuration is
typically a collection of IP addresses. This results in optimistic encryption.
Which a name, we can trivially upgrade to full TLS using PKI. DANE would
pose the issue that we need to perform the DNS queries for DANE before we
have fully established a DNS process. Note that worst base, DNSSEC valition
may also generate additonal DNS queries even if RFC 9102 is used.

For DoH we need to have a name. In fact, we need a URL. This means that
the DoH process likely needs Do53 or DoT to resolve the name. And then
the TLS process and Happy Eyeballs could be used to establish a TLS socket.
Note that is different from Do53 and DoT where typical implementations
support at most three address in /etc/resolv.conf. So we can just try
all three of them (with suitable timeouts).

The fourth DNS process is a recursive resolver. Configuation information
the address of the root DNS servers. For now we assume that all communication
is Do53.

A DNSSEC process receives a stream of DNS queries and produces a stream
of DNSSEC validated DNS replies. The process receives from a trust-anchor
process material to validate the root zone. A DNSSEC process needs access to
a DNS process.

A Trust Anchor process reads trust anchor material from the local filesystem
and needs recent material from root zone to validate. If the local 
trust anchor material is not working, RFC 7958 can be used to fetch
trust anchor material. this requires a TLS socket (or potentially a TCP
socket).

## Orchestration. 

Orchestration can be implicit or explicit. Implicit orchestration means that
processes themselves create required processes. For example, the API could
create a TLS process, which would create a Happy Eyeballs and a DNSSEC 
process (for DANE). The Happy Eyeballs process would also create a 
DNSSEC process, etc. Disavantage is that control over the runtime is
indirect.

With explict orchestration a separate orchestration process creates the
required processes and connects them. The big question is whether or not
the orchestration process become too complex to understand. If we need a lot
of interposing, it may also slow things down.

v0.1 2021-11-05
