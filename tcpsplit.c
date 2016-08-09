
/* tcpsplit
 * Mark Allman (mallman@icir.org)
 * 
 * Copyright (c) 2004--2013 International Computer Science Institute
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * The names and trademarks of copyright holders may not be used in
 * advertising or publicity pertaining to the software without specific
 * prior permission. Title to copyright in this software and any
 * associated documentation will at all times remain with the copyright
 * holders.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include "tcpsplit.h"

char *readfile = NULL;
char *writespec = NULL;
unsigned short num_files = 0;
struct pkt_dump_file out_file [MAX_OUTPUT_FILES];
struct pkt_dump_file weirdf;
pcap_t *inputp = NULL;
unsigned short use_ip_addr = FALSE;
unsigned short use_slash_24 = FALSE;
unsigned short deterministic = FALSE;
int exclude_ports[32] = {0};
int tcp_only = FALSE;

void usage (progname)
char *progname;
{
    fprintf (stderr,"usage: %s [options] readfile writespec num_files\n", 
	     progname);
    fprintf (stderr,"  the \"writespec\" must contain a %%d, indicating ");
    fprintf (stderr,"where to insert the file number\n");
    fprintf (stderr,"  options:\n");
    fprintf (stderr,"    --24      use /24 of IP address in classification\n");
    fprintf (stderr,"    -d        classify deterministically\n");
    fprintf (stderr,"    -h        usage instructions\n");
    fprintf (stderr,"    --use_ip  only use IP addresses in classification\n");
    fprintf (stderr,"    --exclude_ports  comma-separated list of TCP ports to exclude\n");
    fprintf (stderr,"    --tcp_only strip any non-TCP packets\n");
    fprintf (stderr,"    --version version information\n");
    exit (1);
}


void parseargs (argc,argv)
int argc;
char *argv [];
{
    char *p;
    const char *s;
    int i;
    const char delim[] = ",";
    int j;

    for (i = 1; i < argc; i++)
    {
	    if (!strcmp (argv [i],"-h"))
	        usage (argv [0]);
    	if (!strcmp (argv [i],"--version"))
    	{
    	    fprintf (stdout,"tcpsplit v%s\n", VERSION);
    	    exit (0);
    	}
    	if (!strcmp (argv [i],"--use_ip"))
    	    use_ip_addr = TRUE;
        else if ((s = strstr (argv [i],"--exclude_ports")))
        {
            s+=15; /* --exclude_ports */
            s+=1;  /* skip = */
            do {
                size_t field_len = strcspn(s, delim);
                exclude_ports[j] = atoi(s);
                j++;
                s += field_len;
            } while (*s++);

            continue;
        }
        else if (!strcmp (argv [i],"--tcp_only"))
            tcp_only = TRUE;
        else if (!strcmp (argv [i],"--24"))
            use_slash_24 = TRUE;
        else if (!strcmp (argv [i],"-d"))
            deterministic = TRUE;
    	else if (readfile == NULL)
    	    readfile = argv [i];
    	else if (writespec == NULL)
    	{
    	    if ((p = strstr (argv [i],"%")) == NULL)
    	    {
        		fprintf (stderr,"bad write file format (1):\n");
        		fprintf (stderr," format must contain %%d\n");
        		exit (1);
	        }
	        if (*(++p) != 'd')
	        {
		        fprintf (stderr,"bad write format (2):\n");
		        fprintf (stderr," format must not contain arguments other ");
		        fprintf (stderr,"than %%d\n");
		        exit (1);
	        }
	        if (strstr (p,"%") != NULL)
	        {
		        fprintf (stdout,"bad write format (3):\n");
		        fprintf (stdout," too many arguments in format\n");
		        exit (1);
	        }
	        writespec = argv [i];
    	}
    	else if (num_files == 0)
    	{
	        num_files = atoi (argv [i]);
	        if (num_files > MAX_OUTPUT_FILES)
	        {
    	    	fprintf (stderr,"tcpsplit only supports %d output files\n",
    			 MAX_OUTPUT_FILES);
        		exit (1);
	        }
	    }
	    else
	        usage (argv [0]);
    }
    if ((readfile == NULL) || (writespec == NULL) || (num_files == 0))
        usage (argv [0]);
}


void open_trace_files ()
{
    char errbuf [PCAP_ERRBUF_SIZE];
    char *filename;
    char *p;
    unsigned short i;

    if ((inputp = pcap_open_offline (readfile, errbuf)) == NULL)
    {
	    fprintf (stderr,"error opening tracefile %s: %s\n", readfile, errbuf);
	    exit (1);
    }
    if ((filename = (char *)malloc (strlen (writespec) + 10)) == NULL)
    {
	    fprintf (stderr,"open_trace_files() memory allocation problem\n");
	    exit (1);
    }
    for (i = 0; i < num_files; i++)
    {
	    sprintf (filename,writespec,i);
	    if ((out_file [i].dp = pcap_dump_open (inputp,filename)) == NULL)
	    {
	        fprintf (stderr,"cannot open %s for writing\n", filename);
	        exit (1);
    	}
    	out_file [i].pkts = 0;
    }
    p = strstr (writespec,"%d") + 1;
    *p = 's';
    sprintf (filename,writespec,"weird");
    if ((weirdf.dp = pcap_dump_open (inputp,filename)) == NULL)
    {
	    fprintf (stderr,"cannot open %s for writing\n", filename);
	    exit (1);
    }
}


void process_trace ()
{
    struct pcap_pkthdr hdr;
    struct ip *iph;
    struct tcphdr *tcph;
    u_char *pkt;
    unsigned int src_ip, dst_ip;
    unsigned short fn;
    unsigned short offset;
    unsigned short src_port, dst_port;
    unsigned short found_ip_hdr;
    unsigned short proc_etherhdr;
    unsigned short eth_type;
    int j;

    while ((pkt = (u_char *)pcap_next (inputp,&hdr)) != NULL)
    {
        if (hdr.caplen < (EH_SIZE + sizeof (struct ip)))
        {
            pcap_dump ((u_char *)weirdf.dp,&hdr,(u_char *)pkt);
            continue;
        }
        /* VLAN tag processing from Robert Bullen */
        offset = EH_TYPE_OFFSET;
        proc_etherhdr = TRUE;
        found_ip_hdr = FALSE;
        while (proc_etherhdr)
        {
            eth_type = ntohs (*((unsigned short*) (pkt + offset)));
            switch (eth_type)
            {
                case 0x0800:      /* IPv4 */
                    proc_etherhdr = FALSE;
                    found_ip_hdr = TRUE;
                    offset += 2;
                    break;
                case 0x8100:      /* IEEE 802.1Q (VLAN-tagging TPID) */
                case 0x88a8:      /* IEEE 802.1ad (provider-tagging TPID) */
                case 0x9100:      /* IEEE 802.1QinQ (double-tagging TPID) */
                case 0x9200:      /* IEEE 802.1QinQ (alternate TPID) */
                case 0x9300:      /* IEEE 802.1QinQ (alternate TPID) */
                    offset += 4;
                    break;
                case 0x8926:      /* Cisco VNTag (for FET and UMC). */
                    offset += 6;
                    break;
                default:
                    proc_etherhdr = FALSE;
                    found_ip_hdr = FALSE;
                    break;
            }
        }
        if (!found_ip_hdr)
        {
            pcap_dump ((u_char *)weirdf.dp,&hdr,(u_char *)pkt);
            continue;
        }
        iph = (struct ip *)(pkt + offset);
        if (iph == NULL)
        {
            pcap_dump ((u_char *)weirdf.dp,&hdr,(u_char *)pkt);
            continue;
        }
        src_ip = iph->ip_src.s_addr;
        dst_ip = iph->ip_dst.s_addr;
        if (use_slash_24)
        {
            src_ip = ntohl (src_ip) & SLASH24;
            dst_ip = ntohl (dst_ip) & SLASH24;
        }
        offset += (iph->ip_hl * 4);
        if (use_ip_addr || (iph->ip_p != IPPROTO_TCP) || 
            (hdr.caplen < (offset + 4))) {
            src_port = dst_port = 0;
            if (tcp_only) goto skip; /* skip */
        }
        else 
        {
            tcph = (struct tcphdr *)(pkt + offset);
            src_port = htons(tcph->source);
            dst_port = htons(tcph->dest);

            for (j=0; j<sizeof(exclude_ports); j++) {
                if (exclude_ports[j] == 0) continue;
                else if (exclude_ports[j] == src_port || exclude_ports[j] == dst_port) {
                    goto skip;
                }
            }
skip: continue;
        }
        fn = get_file_num (src_ip,dst_ip,src_port,dst_port);
        pcap_dump ((u_char *)out_file [fn].dp,&hdr,(unsigned char *)pkt);
        out_file [fn].pkts++;
    }
}


void close_trace_files ()
{
    unsigned short i;

    pcap_close (inputp);
    for (i = 0; i < num_files; i++)
	pcap_dump_close (out_file [i].dp);
}


int main (argc,argv)
int argc;
char *argv [];
{
    parseargs (argc,argv);
    open_trace_files ();
    init_hash_table ();
    process_trace ();
    close_trace_files ();
    exit (0);
}
