/* ISC license. */

#include <string.h>

#include <skalibs/bytestr.h>
#include <skalibs/sgetopt.h>
#include <skalibs/buffer.h>
#include <skalibs/fmtscan.h>
#include <skalibs/strerr2.h>
#include <skalibs/djbunix.h>
#include <skalibs/ip46.h>

#include <s6-dns/s6dns-constants.h>

#define USAGE "dnsfunnel-translate [ -i resolvconf ] [ -o cachelist ] [ -x ignoredip ]"
#define dieusage() strerr_dieusage(100, USAGE)


static size_t parse_nameservers (ip46 *list, char const *file, char const *ignore)
{
  static char const zero[SKALIBS_IP_SIZE] = { 0 } ;
  char buf[4096] ;
  size_t n = 0, i = 0 ;
  ssize_t len = openreadnclose(file, buf, 4095) ;
  if (len < 0) strerr_diefu2sys(111, "open ", file) ;
  buf[len++] = '\n' ;
  while ((i < len) && (n < S6DNS_MAX_SERVERS))
  {
    size_t j = byte_chr(buf + i, len - i, '\n') ;
    if ((i + j < len) && (j > 13U) && !memcmp("nameserver", buf + i, 10))
    {
      size_t k = 0 ;
      while ((buf[i+10+k] == ' ') || (buf[i+10+k] == '\t')) k++ ;
      if (k && ip46_scan(buf+i+10+k, list + n)
       && memcmp(list[n].ip, zero, SKALIBS_IP_SIZE)
       && (ip46_is6(list + n) || memcmp(list[n].ip, ignore, 4))
      ) n++ ;
    }
    i += j + 1 ;
  }
  return n ;
}


int main (int argc, char const *const *argv)
{
  ip46 list[S6DNS_MAX_SERVERS] = { IP46_ZERO } ;
  char const *resolvconf = "/etc/resolv.conf" ;
  char const *cachelist = "/run/dnsfunnel/root/caches" ;
  char ignore[4] = "\177\0\0\1" ;
  size_t n ;
  PROG = "dnsfunnel-translate" ;
  {
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "i:o:x:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'i' : resolvconf = l.arg ; break ;
        case 'o' : cachelist = l.arg ; break ;
        case 'x' : if (!ip4_scan(l.arg, ignore)) dieusage() ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }

  n = parse_nameservers(list, resolvconf, ignore) ;
  if (!n) strerr_dief2x(1, "no suitable cache address in ", resolvconf) ;

  {
    char buf[4096] ;
    buffer b ;
    int fd = openc_trunc(cachelist) ;
    if (fd < 0) strerr_diefu2sys(111, "open ", cachelist) ;
    buffer_init(&b, &buffer_write, fd, buf, 4096) ;
    for (size_t i = 0 ; i < n ; i++)
    {
      char fmt[IP46_FMT] ;
      size_t len = ip46_fmt(fmt, list + i) ;
      fmt[len++] = '\n' ;
      if (buffer_put(&b, fmt, len) < len)
        strerr_diefu2sys(111, "write to ", cachelist) ;
    }
    if (!buffer_flush(&b))
      strerr_diefu2sys(111, "write to ", cachelist) ;
  }
  return 0 ;
}
