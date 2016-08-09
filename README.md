# tcpsplit

Based on the original version by Mark Allman

tcpsplit v0.3
August 2016

Mark Allman
International Computer Science Institute
mallman@icir.org


This utility takes a libpcap packet trace and splits it into some
number of smaller traces, along TCP connection boundaries.  This
allows the breaking apart of large traces into smaller and more
manageable subsets without ending up with part of a TCP connection
in one sub-trace and part in another.

Basic usage:

usage: tcpsplit [options] readfile writespec num_files
  the "writespec" must contain a %d, indicating where to insert the file number
  options:
    --24      use /24 of IP address in classification
    -d        classify deterministically
    -h        usage instructions
    --notcp   only use IP addresses in classification
    --version version information

Examples:

% tcpsplit bigtrace smalltrace.%d 5

    This creates 5 sub-traces called "smalltrace.1", "smalltrace.2",
    etc. from "bigtrace".

In addition, the tool always creates a "weird" file (in this case it
would be "smalltrace.weird").  This file contains any packets that
could not successfully be classified and put into another of the
files.  Normally, this file contains no packets.

Default behavior:

  - Each TCP segment is dumped into a sub-trace based on the two IP
    addresses and two port numbers in the packet.  Each time a new
    connection is detected the file the connection will be dumped in
    is picked based on a least-frequently used scheme (in terms of
    packets / sub-trace).
 
  - Each non-TCP segment is dumped into a sub-trace based on the two
    IP addresses only.

Options:

  - If the "--notcp" option is given then the TCP port numbers are
    never used in determining which sub-trace packets are filed
    into.  (This is useful for collecting all traffic between two
    endpoints together.)

  - If the "-d" option is given the sub-trace is chosen via a hash
    of the IPs and ports instead of the LFU scheme sketched above.
    This provides a deterministic mapping to sub-traces.

  - If the "--24" option is given, only the high-order 24 bits of
    the IPs are used for classification.

Building:

  * The tool requires libpcap be installed.

  * The tool was developed under FreeBSD.  More recently the tool
    has been maintained under OSX.  Running "make" will build
    tcpsplit on either of these.

  * The tool also has been tested and used regularly under Linux
    (build with "make -f Makefile.linux").

  * The tool has been built and used under Solaris (build with "make
    -f Makefile.solaris") long ago.  It may or may not work.  Also,
    Rick Jones made it work under HP-UX 11.11.  I do not have ready
    access to either of these systems these days and therefore
    cannot vouch for the tool continuing to work in these
    environments. 

  * Yes, I am too stupid to use autoconf.

Please let me know if you have tweaks or comments.



Acknowledgments
---------------
Robert Bullen - added code to grok VLAN headers
Rick Jones - tweaks for compiling under HP-UX 11.11
Jim Wyllie - signedness bug fixes
