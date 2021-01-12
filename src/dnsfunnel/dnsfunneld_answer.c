/* ISC license. */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include <skalibs/error.h>
#include <skalibs/strerr2.h>
#include <skalibs/genqdyn.h>
#include <skalibs/socket.h>

#include <s6-dns/s6dns-message.h>

#include "dnsfunneld.h"

typedef struct dfanswer_s dfanswer_t, *dfanswer_t_ref ;
struct dfanswer_s
{
  char buf[512] ;
  char ip[4] ;
  uint16_t port ;
} ;
#define DFANSWER_ZERO { .buf = { 0 }, .ip = "\0\0\0", .port = 0 }

static genqdyn dfanswers = GENQDYN_INIT(dfanswer_t, 1, 8) ;

size_t dfanswer_pending ()
{
  return (dfanswers.queue.len - dfanswers.head) / dfanswers.esize ;
}

static void dfanswer_push (char const *s, size_t len, uint32_t ip, uint16_t port)
{
  if (len > 510)
  {
    if (verbosity)
      strerr_warnw1x("answer too big, dropping - enable truncation to avoid this") ;
  }
  else
  {
    dfanswer_t ans = { .port = port } ;
    uint16_pack_big(ans.buf, len) ;
    memcpy(ans.buf + 2, s+2, len) ;
    uint32_pack_big(ans.ip, ip) ;
    if (!genqdyn_push(&dfanswers, &ans))
      strerr_diefu1sys(111, "queue answer to client") ;
  }
}

int dfanswer_flush ()
{
  while (dfanswer_pending())
  {
    dfanswer_t *ans = GENQDYN_PEEK(dfanswer_t, &dfanswers) ;
    uint16_t len ;
    uint16_unpack_big(ans->buf, &len) ;
    if (socket_send4(0, ans->buf, len, ans->ip, ans->port) < 0)
      return error_isagain(errno) ? (errno = 0, 0) : -1 ;
    genqdyn_pop(&dfanswers) ;
  }
  return 1 ;
}

void dfanswer_fail (dfquery_t const *q)
{
  char buf[510] ;
  uint16_t len ;
  s6dns_message_header_t hdr ;
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
  dfanswer_push(buf, len, q->ip, q->port) ;
}

void dfanswer_nxdomain (dfquery_t const *q)
{
  char buf[510] ;
  uint16_t len ;
  s6dns_message_header_t hdr ;
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
  dfanswer_push(buf, len, q->ip, q->port) ;
}

void dfanswer_nodata (dfquery_t const *q)
{
  char buf[510] ;
  uint16_t len ;
  s6dns_message_header_t hdr ;
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
