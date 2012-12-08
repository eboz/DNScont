DNScont 1.0
=======
 *
 * by eboz
 * send your bugs and complains to eb0z@hotmail.com
 *
 * a pseudo DNS script that uses stateless TCP
 *
 * the assumption here is that the host system
 * - uses an ethernet interface
 * - does not already run a listener on tcp port 53
 * - does not use the kernel blackhole facility. i.e.
 *    sysctl -w net.inet.tcp.blackhole=2
 *    sysctl -w net.inet.udp.bkackhole=1
 *
 * the routine uses the libpcap libraries (www.tcpdump.org)
 * and the IP raw socket interface to fake out a tCP 
 * connection
 *
 * it uses a UDP connection to a backend DNS server
 *
 * this is very much a crude proof of concept exercise - it does not
 * attempt to interpret any flags about transport or buffer size
 * or react to truncated responses - it simply maps the TCP query to a UDP
 * query (by stripping out the query size leading field) and maps the UDP 
 * response to a TCP response (by adding the same length field back in)
 * Doubtless the entire mapping function could be improved, but it really
 * wasn't the intention to make this into a robust DNS proxy. The intention
 * was to show that TCP DNS client queries could be served from a stateless
 * TCP server. 
 *
 * compilation:
 *  gcc -lpcap -o DNScont DNScont.c
 *
 * execution: 
 *  sudo dnscont <Interface_device_name>
 *
 * this program uses constants for the local IP address and CHANGES it, can be used for domain-hijacking sessions also.