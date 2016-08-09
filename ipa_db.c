
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
#include <strings.h>
#include "tcpsplit.h"

struct ip_pair *pairs [HASH_TBL_SIZE];


void init_hash_table ()
{
    bzero (pairs,sizeof (struct ip_pair *) * HASH_TBL_SIZE);
}


#ifdef OLD
/* Previous hash function.  Result depends on the byte processing order,
   which is suboptimal for our task. */
unsigned int hashf (array,sz,hash)
char *array;
unsigned int sz;
unsigned int hash;
{
    unsigned int h;
    unsigned int i;

    h = hash;
    for (i = 0; i < sz; i++)
	h = (h * HASH_MULTIPLIER) + array [i];
    return (h);
}
#endif /* OLD */


unsigned int hashf (array,sz,hash)
char *array;
unsigned int sz;
unsigned int hash;
{
    unsigned int h = hash;
    unsigned int i;

    for (i = 0; i < sz; i++)
        if (array [i] > 0)
            h *= array [i];
    return (h);
}


unsigned short get_file_num (src_ip,dst_ip,src_tcp,dst_tcp)
unsigned int src_ip, dst_ip;
unsigned short src_tcp, dst_tcp;
{
    struct ip_pair *p;
    struct ip_pair *newp;
    unsigned int hash = 0;

    /* Using only two bytes of the IPs in the hash or the hash space will
       explode.  --allman */
    hash = hashf (&src_ip,2,1);
    hash = hashf (&dst_ip,2,hash);
    if (src_tcp)
        hash = hashf (&src_tcp,2,hash);
    if (dst_tcp)
        hash = hashf (&dst_tcp,2,hash);
    hash = hash % HASH_TBL_SIZE;
    if (deterministic)
        return (hash % num_files);
    if (pairs [hash] != NULL)
    {
        for (p = pairs [hash]; p != NULL; p = p->next)
        {
            if ((!memcmp (&src_ip,&p->ip1,4) &&
                 !memcmp (&dst_ip,&p->ip2,4) &&
                 !memcmp (&src_tcp,&p->port1,2) &&
                 !memcmp (&dst_tcp,&p->port2,2)) ||
                (!memcmp (&dst_ip,&p->ip1,4) && 
                 !memcmp (&src_ip,&p->ip2,4) &&
                 !memcmp (&dst_tcp,&p->port1,2) &&
                 !memcmp (&src_tcp,&p->port2,2)))
                return (p->file_num);
        }
    }
    if ((newp = (struct ip_pair *)malloc (sizeof (struct ip_pair))) == NULL)
    {
	fprintf (stderr,"not enough memory to allocate another IP pair\n");
	exit (1);
    }
    memcpy (&newp->ip1,&src_ip,4);
    memcpy (&newp->ip2,&dst_ip,4);
    memcpy (&newp->port1,&src_tcp,2);
    memcpy (&newp->port2,&dst_tcp,2);
    newp->next = pairs [hash];
    pairs [hash] = newp;
    newp->file_num = file_for_new_cnn ();
    return (newp->file_num);
}
