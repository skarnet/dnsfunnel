/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

#include <skalibs/uint32.h>
#include <skalibs/types.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/error.h>
#include <skalibs/bitarray.h>
#include <skalibs/strerr2.h>
#include <skalibs/sgetopt.h>
#include <skalibs/stralloc.h>
#include <skalibs/sig.h>
#include <skalibs/socket.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/iopause.h>
#include <skalibs/selfpipe.h>
#include <skalibs/gensetdyn.h>

#include <s6-dns/s6dns.h>

#include "dnsfunneld.h"

#define USAGE "dnsfunneld [ -v verbosity ] [ -d notif ] [ -o operations ] cachelist"
#define dieusage() strerr_dieusage(100, USAGE)

#define DNSFUNNELD_INPUT_MAX 64

unsigned int verbosity = 1 ;
static tain_t globaltto = TAIN_INFINITE_RELATIVE ;
static int cont = 1 ;
static char const *cachelistfile = 0 ;
static s6dns_ip46list_t cachelist ;
static uint32_t ops = 0 ;

static inline void X (void)
{
  strerr_dief1x(101, "internal inconsistency. Please submit a bug-report.") ;
}

static inline void s6dns_ip46list_copy (s6dns_ip46list_t *dst, ip46full_t const *src, size_t n)
{
  if (n >= S6DNS_MAX_SERVERS) n = S6DNS_MAX_SERVERS - 1 ;
  for (size_t i = 0 ; i < n ; i++)
  {
    memcpy(dst->ip + i * SKALIBS_IP_SIZE, src[i].ip, SKALIBS_IP_SIZE) ;
#ifdef SKALIBS_IPV6_ENABLED
    bitarray_poke(dst->is6, i, ip46_is6(src + i)) ;
#endif
  }
  memset(dst->ip + n * SKALIBS_IP_SIZE, 0, SKALIBS_IP_SIZE) ;
}

static int load_cachelist (int initial)
{
  char buf[4096] ;
  ip46full_t list[S6DNS_MAX_SERVERS] ;
  size_t n ;
  ssize_t r = openreadnclose_nb(cachelistfile, buf, 4095) ;
  if (r < 0) return -1 ;
  buf[r++] = 0 ;
  ip46_scanlist(list, S6DNS_MAX_SERVERS, buf, &n) ;
  if (!n) return -2 ;
  s6dns_ip46list_copy(&cachelist, list, n) ;
  return 0 ;
}

static inline void handle_signals (void)
{
  for (;;)
  {
    switch (selfpipe_read())
    {
      case -1 : strerr_diefu1sys(111, "read from selfpipe") ;
      case 0 : return ;
      case SIGTERM : cont = 0 ; break ;
      case SIGHUP :
      {
        switch (load_cachelist(0))
        {
          case 0 : query_process_reload() ; break ;
          case -1 : strerr_warnwu2sys("read ", cachelistfile) ; break ;
          case -2 : strerr_warnw2x("invalid cache list in ", cachelistfile) ; break ;
          default : X() ;
        }
        break ;
      }
      default : X() ;
    }
  }
}

static dfquery_t const dfquery_zero = DFQUERY_ZERO ;
static gensetdyn queries = GENSETDYN_INIT(dfquery_t, 16, 3, 8) ;
static uint32_t sentinel ;
#define inflight (gensetdyn_n(&queries) - 1)
#define QUERY(i) GENSETDYN_P(dfquery_t, &queries, i)

void query_new (s6dns_domain_t const *d, uint16_t qtype, uint16_t id, uint32_t ip, uint16_t port, uint32_t procid)
{
  dfquery_t q =
  {
    .next = QUERY(sentinel)->next,
    .xindex = 0,
    .procid = procid,
    .ip = ip,
    .port = port,
    .id = id,
    .dt = S6DNS_ENGINE_ZERO
  } ;
  tain_t deadline ;
  uint32_t i ;
  if (!gensetdyn_new(&queries, &i))
    strerr_diefu1sys(111, "create new query") ;
  tain_add_g(&deadline, &globaltto) ;
  if (!s6dns_engine_init_g(&q.dt, &cachelist, S6DNS_O_RECURSIVE, d->s, d->len, qtype, &deadline))
    strerr_diefu1sys(111, "start new query") ;
  *QUERY(i) = q ;
  QUERY(sentinel)->next = i ;
}

static inline void sanitize_and_new (char const *buf, unsigned int len, char const *ippack, uint16_t port)
{
  s6dns_domain_t d ;
  uint32_t ip ;
  unsigned int pos ;
  s6dns_message_header_t hdr ;
  s6dns_message_counts_t counts ;
  uint16_t qtype ;
  if (!s6dns_message_parse_init(&hdr, &counts, buf, len, &pos)
   || hdr.qr
   || hdr.opcode
   || !hdr.rd
   || hdr.counts.qd != 1 || hdr.counts.an || hdr.counts.ns || hdr.counts.nr
   || !s6dns_message_parse_question(&counts, &d, &qtype, buf, len, &pos))
    return ;
  uint32_unpack_big(ippack, &ip) ;
  if (ops) query_process_question(ops, &d, qtype, hdr.id, ip, port) ;
  else query_new(&d, qtype, hdr.id, ip, port, 0) ;
}

int main (int argc, char const *const *argv)
{
  int spfd = -1 ;
  int notif = -1 ;
  PROG = "dnsfunneld" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "v:d:o:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'v' : if (!uint0_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'd' : if (!uint0_scan(l.arg, (unsigned int *)&notif)) dieusage() ; break ;
        case 'o' : if (!uint320_scan(l.arg, &ops)) dieusage() ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (!argc) dieusage() ;
  }
  if (notif >= 0)
  {
    if (notif < 3) strerr_dief1x(100, "notification fd must be 3 or more") ;
    if (fcntl(notif, F_GETFD) < 0) strerr_dief1sys(100, "invalid notification fd") ;
  }

  if (ndelay_on(0) < 0) strerr_diefu1sys(111, "turn stdin non-blocking") ;
  if (sig_ignore(SIGPIPE) < 0) strerr_diefu1sys(111, "ignore SIGPIPE") ;
  cachelistfile = argv[0] ;
  switch (load_cachelist(1))
  {
    case 0 : break ;
    case -1 : strerr_diefu2sys(111, "read ", cachelistfile) ;
    case -2 : strerr_dief2x(100, "invalid cache list in ", cachelistfile) ;
    default : X() ;
  }
  if (!s6dns_init()) strerr_diefu1sys(111, "s6dns_init") ;
  spfd = selfpipe_init() ;
  if (spfd < 0) strerr_diefu1sys(111, "init selfpipe") ;
  {
    sigset_t set ;
    sigemptyset(&set) ;
    sigaddset(&set, SIGTERM) ;
    sigaddset(&set, SIGHUP) ;
    if (selfpipe_trapset(&set) < 0) strerr_diefu1sys(111, "trap signals") ;
  }
  if (!gensetdyn_new(&queries, &sentinel))
    strerr_diefu1sys(111, "initialize query structure") ;
  *QUERY(sentinel) = dfquery_zero ;
  QUERY(sentinel)->next = sentinel ;
  if (!query_process_init())
    strerr_diefu1sys(111, "initialize query processing") ;
  tain_now_set_stopwatch_g() ;

  if (notif >= 0)
  {
    fd_write(notif, "\n", 1) ;
    fd_close(notif) ;
  }
                  
  for (;;)                
  {
    tain_t deadline = TAIN_INFINITE ;
    uint32_t i = QUERY(sentinel)->next ;
    uint32_t j = 2 ;
    int r ;
    iopause_fd x[2 + inflight] ;
  
    x[0].fd = spfd ;
    x[0].events = IOPAUSE_READ ;
    x[1].fd = 0 ;
    x[1].events = (cont ? IOPAUSE_READ : 0) | (dfanswer_pending() ? IOPAUSE_WRITE : 0) ;
    if (!x[1].events && !inflight) break ;

    while (i != sentinel)
    {
      dfquery_t *q = QUERY(i) ;
      s6dns_engine_nextdeadline(&q->dt, &deadline) ;
      x[j].fd = q->dt.fd ;
      x[j].events = 0 ;
      if (s6dns_engine_isreadable(&q->dt)) x[j].events |= IOPAUSE_READ ;
      if (s6dns_engine_iswritable(&q->dt)) x[j].events |= IOPAUSE_WRITE ;
      q->xindex = j++ ;
      i = q->next ;
    }

    r = iopause_g(x, j, &deadline) ;
    if (r < 0) strerr_diefu1sys(111, "iopause") ;

    if (!r) 
    {
      i = QUERY(sentinel)->next ;
      j = sentinel ;
      while (i != sentinel)
      {
        dfquery_t *q = QUERY(i) ;
        uint32_t k = q->next ;
        if (s6dns_engine_timeout_g(&q->dt))
        {
          query_process_response_failure(ops, q) ;
          QUERY(j)->next = k ;
          stralloc_free(&q->dt.sa) ;
          gensetdyn_delete(&queries, i) ;
        }
        else j = i ;
        i = k ;
      }
      continue ;
    }

    if (x[0].revents & IOPAUSE_READ) handle_signals() ;

    if (x[1].revents & IOPAUSE_WRITE)
    {
      int r = dfanswer_flush() ;
      if (r < 0) strerr_diefu1sys(111, "send DNS answer to client") ;
    }
                        
    i = QUERY(sentinel)->next ;
    j = sentinel ;
    while (i != sentinel)
    {
      dfquery_t *q = QUERY(i) ;
      uint32_t k = q->next ;
      int r = s6dns_engine_event_g(&q->dt) ;
      if (r)
      {
        if (r > 0) query_process_response_success(ops, q) ;
        else query_process_response_failure(ops, q) ;
        QUERY(j)->next = k ;
        if (r > 0) s6dns_engine_free(&q->dt) ;
        else stralloc_free(&q->dt.sa) ;
        gensetdyn_delete(&queries, i) ;
      }
      else j = i ;
      i = k ;
    }

    if (x[0].revents & IOPAUSE_READ)
    {
      uint32_t n = DNSFUNNELD_INPUT_MAX ;
      while (n--)
      {
        char ip[4] ;
        uint16_t port ;
        char buf[512] ;
        ssize_t r = socket_recv4(0, buf, 512, ip, &port) ;
        if (r < 0)
          if (error_isagain(errno)) break ;
          else strerr_diefu1sys(111, "socket_recv") ;
        else if (!r) continue ;
        else sanitize_and_new(buf, r, ip, port) ;
      }
    }
  }
  return 0 ;
}
