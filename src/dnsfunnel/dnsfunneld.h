/* ISC license. */

#ifndef DNSFUNNELD_H
#define DNSFUNNELD_H

#include <stddef.h>
#include <stdint.h>

#include <skalibs/gensetdyn.h>
#include <skalibs/ip46.h>

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-engine.h>

typedef struct dfquery_s dfquery_t, *dfquery_t_ref ;
struct dfquery_s
{
  uint32_t prev ;
  uint32_t next ;
  uint32_t xindex ;
  uint32_t procid ;
  char ip[SKALIBS_IP_SIZE] ;
  uint16_t port ;
  uint16_t id ;
  s6dns_engine_t dt ;
} ;
#define DFQUERY_ZERO { .prev = 0, .next = 0, .xindex = 0, .procid = 0, .ip = { 0 }, .port = 0, .id = 0, .dt = S6DNS_ENGINE_ZERO }

extern unsigned int verbosity ;
extern unsigned int ipsz ;
extern size_t dfanswer_pending (void) ;
extern int dfanswer_flush (void) ;
extern void dfanswer_fail (dfquery_t const *, int) ;
extern void dfanswer_nxdomain (dfquery_t const *, int) ;
extern void dfanswer_nodata (dfquery_t const *, int) ;
extern void dfanswer_pass (dfquery_t const *, char *, unsigned int) ;

extern void query_new (s6dns_domain_t const *, uint16_t, uint16_t, char const *, uint16_t, uint32_t) ;

extern int query_process_init (void) ;
extern void query_process_reload (void) ;
extern void query_process_question (uint32_t, s6dns_domain_t const *, uint16_t, uint16_t, char const *, uint16_t) ;
extern void query_process_response_failure (uint32_t, dfquery_t const *) ;
extern void query_process_response_success (uint32_t, dfquery_t const *) ;

#endif
