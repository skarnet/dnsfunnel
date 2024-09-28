/* ISC license. */

#include <stdint.h>

#include <skalibs/uint16.h>
#include <skalibs/strerr.h>
#include <skalibs/gensetdyn.h>

#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-engine.h>

#include "dnsfunneld.h"

static gensetdyn rinfo = GENSETDYN_INIT(uint8_t, 16, 3, 8) ;
#define RINFO(i) GENSETDYN_P(uint8_t, &rinfo, i)

int query_process_init ()
{
  return 1 ;
}

void query_process_reload ()
{
}

void query_process_question (uint32_t ops, s6dns_domain_t const *d, uint16_t qtype, uint16_t id, char const *ip, uint16_t port)
{
  if (ops & 2 && (qtype == S6DNS_T_A || qtype == S6DNS_T_AAAA))
  {
    uint32_t i ;
    if (!gensetdyn_new(&rinfo, &i)) strerr_diefu1sys(111, "process query") ;
    *RINFO(i) = (qtype == S6DNS_T_AAAA) << 7 ;
    query_new(d, S6DNS_T_A, id, ip, port, i+1) ;
    query_new(d, S6DNS_T_AAAA, id, ip, port, i+1) ; 
  }
  else query_new(d, qtype, id, ip, port, 0) ;
}

static inline unsigned int truncate_packet (char *s, unsigned int olen)
{
  s6dns_message_header_t hdr ;
  s6dns_message_counts_t counts ;
  unsigned int section ;
  unsigned int pos ;
  if (!s6dns_message_parse_init(&hdr, &counts, s, olen, &pos)) return 0 ;
  if (hdr.rcode) return 0 ;
  section = s6dns_message_parse_skipqd(&counts, s, olen, &pos) ;
  while (section)
  {
    s6dns_message_rr_t rr ;
    s6dns_message_counts_t newcounts = counts ;
    unsigned int tmp = pos ;
    if (!s6dns_message_parse_getrr(&rr, s, olen, &tmp)) return 0 ;
    section = s6dns_message_parse_next(&newcounts, &rr, s, olen, &tmp) ;
    if (tmp > 512)
    {
      hdr.counts.qd -= counts.qd ;
      hdr.counts.an -= counts.an ;
      hdr.counts.ns -= counts.ns ;
      hdr.counts.nr -= counts.nr ;
      hdr.tc = 1 ;
      s6dns_message_header_pack(s, &hdr) ;
      return pos ;
    }
    pos = tmp ;
    counts = newcounts ;
  }
  return olen ;
}

static inline uint16_t extract_qtype (dfquery_t const *q)
{
  s6dns_domain_t name ;
  uint16_t qtype ;
  uint16_t len ;
  s6dns_message_header_t hdr ;
  s6dns_message_counts_t counts ;
  unsigned int pos ;
  uint16_unpack_big(q->dt.sa.s, &len) ;
  if (!s6dns_message_parse_init(&hdr, &counts, q->dt.sa.s + 2, len, &pos)) return 0 ;
  if (!s6dns_message_parse_question(&counts, &name, &qtype, q->dt.sa.s + 2, len, &pos)) return 0 ;
  return qtype ;
}

static int isnxdomain (dfquery_t const *q)
{
  s6dns_message_header_t hdr ;
  s6dns_message_counts_t counts ;
  unsigned int pos ;
  if (!s6dns_message_parse_init(&hdr, &counts, s6dns_engine_packet(&q->dt), s6dns_engine_packetlen(&q->dt), &pos)) return 0 ;
  return hdr.rcode == 3 ;
}

static int input_event (dfquery_t const *q, unsigned int ev)
{
  static uint8_t const table[5][6] =
  {
    { 0x11, 0x03, 0x81, 0x02, 0x02, 0x04 },
    { 0x06, 0x06, 0x06, 0x05, 0x05, 0x05 },
    { 0x15, 0x25, 0x85, 0x06, 0x06, 0x06 },
    { 0x06, 0x06, 0x06, 0x25, 0x25, 0x45 },
    { 0x15, 0x45, 0x85, 0x06, 0x06, 0x06 }
  } ;
  uint8_t b = *RINFO(q->procid - 1) ;
  uint8_t isaux = 3 * (b >> 7 != (extract_qtype(q) == S6DNS_T_AAAA)) ;
  uint8_t state = b & 7 ;
  uint8_t c = table[state][ev + isaux] ;
  state = c & 7 ;
  *RINFO(q->procid - 1) = (b & 0xf8) | state ;
  if (c & 0x10) dfanswer_fail(q, !!isaux) ;
  if (c & 0x20) dfanswer_nxdomain(q, !!isaux) ;
  if (c & 0x40) dfanswer_nodata(q, !!isaux) ;
  if (state >= 6) strerr_dief1x(101, "problem in main/aux transition table; please submit a bug-report.") ;
  if (state == 5) gensetdyn_delete(&rinfo, q->procid - 1) ;
  return !(c & 0x80) ;
}

void query_process_response_failure (uint32_t ops, dfquery_t const *q)
{
  if (ops & 2 && q->procid && input_event(q, 0)) return ;
  else dfanswer_fail(q, 0) ;
}

void query_process_response_success (uint32_t ops, dfquery_t const *q)
{
  if (ops & 2 && q->procid && input_event(q, 1 + !isnxdomain(q))) return ;
  if (ops & 1 && s6dns_engine_packetlen(&q->dt) > 512)
  {
    unsigned int len = truncate_packet(s6dns_engine_packet(&q->dt), s6dns_engine_packetlen(&q->dt)) ;
    if (!len) dfanswer_fail(q, 0) ;
    else dfanswer_pass(q, s6dns_engine_packet(&q->dt), len) ;
  }
  else dfanswer_pass(q, s6dns_engine_packet(&q->dt), s6dns_engine_packetlen(&q->dt)) ;
}
