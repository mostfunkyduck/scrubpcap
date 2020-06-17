# scrubpcap
Given an input pcap file, this utility will scrub everything above the transport layer to remove sensitive information in the higher level payloads.  Note that IPs are left the same right now, so it's only partially scrubbed.  This will be implemented in the future (and can also be done in tcprewrite (http://tcpreplay.synfin.net/tcprewrite.html)
