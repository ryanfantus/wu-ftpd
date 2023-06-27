/*********************************************************

UDP Packet structure for Auto Tuning Measurements for the
wu-ftpd auto-buf enabled code.
-Gaurav Navlakha, NLANR. June 2001.

*********************************************************/
#ifndef __BUF_UDP_H__
#define __BUF_UDP_H__
#include <sys/time.h>
#include <unistd.h>

typedef struct buf_udp
{
    struct timeval tval;
    int seqno;
} buf_udp_t;

#endif
