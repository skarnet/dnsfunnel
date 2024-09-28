/* ISC license. */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include <skalibs/error.h>
#include <skalibs/strerr.h>
#include <skalibs/stralloc.h>
#include <skalibs/socket.h>

#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-message.h>

#include "dnsfunneld.h"

static stralloc q = STRALLOC_ZERO ;
static size_t head = 0 ;

size_t dfanswer_pending ()
{
  return q.len - head ;
}

static void dfanswer_push (char const *s, size_t len, char const *ip, uint16_t port)
{
  if (len > 512)
  {
    if (verbosity)
      strerr_warnw1x("answer too big, dropping - enable truncation to avoid this") ;
  }
  else
  {
    if (!stralloc_readyplus(&q, len + 4 + ipsz)) strerr_diefu1sys(111, "queue answer to client") ;
    uint16_pack_big(q.s + q.len, port) ; q.len += 2 ;
    uint16_pack_big(q.s + q.len, len) ; q.len += 2 ;
    memcpy(q.s + q.len, ip, ipsz) ; q.len += ipsz ;
    memcpy(q.s + q.len, s, len) ; q.len += len ;
  }
}

int dfanswer_flush ()
{
  while (dfanswer_pending())
  {
    uint16_t port, len ;
    uint16_unpack_big(q.s + head, &port) ;
    uint16_unpack_big(q.s + head + 2, &len) ;
    if ((ipsz == 16 ? socket_send6(0, q.s + head + 20, len, q.s + head + 4, port) : socket_send4(0, q.s + head + 8, len, q.s + head + 4, port)) < 0)
      return error_isagain(errno) ? (errno = 0, 0) : -1 ;
    head += 4 + ipsz + len ;
    if ((q.len - head) >> 2 <= q.len)
    {
      memmove(q.s, q.s + head, q.len - head) ;
      q.len -= head ;
      head = 0 ;
    }
  }
  return 1 ;
}

static void switchaux (char *buf, uint16_t len)
{
  uint16_t qtype ;
  uint16_unpack_big(buf + len - 4, &qtype) ;
  switch (qtype)
  {
    case S6DNS_T_A : qtype = S6DNS_T_AAAA ; break ;
    case S6DNS_T_AAAA : qtype = S6DNS_T_A ; break ;
    default : strerr_dief1x(101, "can't happen: invalid qtype in auxiliary query") ;
  }
  uint16_pack_big(buf + len - 4, qtype) ;
}


void dfanswer_fail (dfquery_t const *q, int isaux)
{
  char buf[512] ;
  s6dns_message_header_t hdr ;
  uint16_t len ;
  uint16_unpack_big(q->dt.sa.s, &len) ;
  memcpy(buf, q->dt.sa.s + 2, len) ;
  s6dns_message_header_unpack(buf, &hdr) ;
  hdr.id = q->id ;
  hdr.qr = 1 ;
  hdr.aa = 0 ;
  hdr.tc = 0 ;
  hdr.rd = 1 ;
  hdr.ra = 1 ;
  hdr.z = 0 ;
  hdr.rcode = 2 ;  /* servfail */
  s6dns_message_header_pack(buf, &hdr) ;
  if (isaux) switchaux(buf, len) ;
  dfanswer_push(buf, len, q->ip, q->port) ;
}

void dfanswer_nxdomain (dfquery_t const *q, int isaux)
{
  char buf[512] ;
  s6dns_message_header_t hdr ;
  uint16_t len ;
  uint16_unpack_big(q->dt.sa.s, &len) ;
  memcpy(buf, q->dt.sa.s + 2, len) ;
  s6dns_message_header_unpack(buf, &hdr) ;
  hdr.id = q->id ;
  hdr.qr = 1 ;
  hdr.aa = 1 ;
  hdr.tc = 0 ;
  hdr.rd = 1 ;
  hdr.ra = 1 ;
  hdr.z = 0 ;
  hdr.rcode = 3 ;  /* nxdomain */
  s6dns_message_header_pack(buf, &hdr) ;
  if (isaux) switchaux(buf, len) ;
  dfanswer_push(buf, len, q->ip, q->port) ;
}

void dfanswer_nodata (dfquery_t const *q, int isaux)
{
  char buf[512] ;
  s6dns_message_header_t hdr ;
  uint16_t len ;
  uint16_unpack_big(q->dt.sa.s, &len) ;
  memcpy(buf, q->dt.sa.s + 2, len) ;
  s6dns_message_header_unpack(buf, &hdr) ;
  hdr.id = q->id ;
  hdr.qr = 1 ;
  hdr.aa = 1 ;
  hdr.tc = 0 ;
  hdr.rd = 1 ;
  hdr.ra = 1 ;
  hdr.z = 0 ;
  hdr.rcode = 0 ;  /* success */
  s6dns_message_header_pack(buf, &hdr) ;
  if (isaux) switchaux(buf, len) ;
  dfanswer_push(buf, len, q->ip, q->port) ;
}

void dfanswer_pass (dfquery_t const *q, char *s, unsigned int len)
{
  s6dns_message_header_t hdr ;
  s6dns_message_header_unpack(s, &hdr) ;
  hdr.id = q->id ;
  s6dns_message_header_pack(s, &hdr) ;
  dfanswer_push(s, len, q->ip, q->port) ;
}
