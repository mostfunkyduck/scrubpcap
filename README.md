# scrubpcap
Given an input pcap file, this utility will scrub everything above the transport layer to remove sensitive information in the higher level payloads.  Note that IPs are left the same right now, so it's only partially scrubbed.

# Usage
`./scrubpcap -inputfile blah.pcap -outputfile blah.stripped.pcap`
