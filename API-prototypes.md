# Prototype Plan

The basic idea is make a series of prototypes with increasing complexity. 

1. A prototype based on getaddrinfo, socket, connect, select and some TLS library like openssl. DNS resolution will be blocking but it should be possible to implement a simple version of Happy Eyeballs. No local DNSSEC validation.
2. A prototype based on libevent. Libevent has an asynchronous stub resolver and abstracts TLS. So it should be possible to implement Happy Eyeballs without limitations. No local DNSSEC validation.
3. A prototype based on Getdns and libevent. It is possible to implements Happy Eyeballs. And Getdns provides local DNSSEC validation.
4. A prototype based on a restructured Getdns that gives the user more control over orchestration.

## Future Work
The first prototypes assume a simple, stable network environment. In the future we should support (wifi) networks that come and go, switch between wifi and mobile, etc.