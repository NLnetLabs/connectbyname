all: dns-client-proxy.txt

dns-client-proxy.txt: dns-client-proxy.xml
	xml2rfc dns-client-proxy.xml

dns-client-proxy.xml: dns-client-proxy.md
	mmark dns-client-proxy.md > dns-client-proxy.xml.new && \
		mv dns-client-proxy.xml.new dns-client-proxy.xml
