/* ISC license. */

#include <skalibs/sysdeps.h>

#ifndef SKALIBS_HASCHROOT
# error "this program can only be built on systems that provide a chroot() function"
#endif

#include <skalibs/nonposix.h>  /* chroot */
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

#include <skalibs/uint16.h>
#include <skalibs/types.h>
#include <skalibs/fmtscan.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/djbunix.h>
#include <skalibs/socket.h>
#include <skalibs/exec.h>

#include <dnsfunnel/config.h>

#define USAGE "dnsfunnel-daemon [ -v verbosity ] [ -d notif ] [ -U | -u uid -g gid ] [ -i ip:port ] [ -R root ] [ -b bufsize ] [ -f cachelist ] [ -T | -t ] [ -N | -n ] "
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  int notif = 0 ;
  unsigned int verbosity = 1 ;
  unsigned int bufsize = 131072 ;
  int flagU = 0 ;
  uid_t uid = -1 ;
  gid_t gid = -1 ;
  char const *ipport = "127.0.0.1:53" ;
  char const *newroot = 0 ;
  char const *cachelist = DNSFUNNEL_DEFAULT_CACHELIST ;
  uint32_t ops = 0 ;
  PROG = "dnsfunnel-daemon" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "v:d:Uu:g:i:R:b:f:TtNn", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'v' : if (!uint0_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'd' : if (!uint0_scan(l.arg, (unsigned int *)&notif)) dieusage() ; break ;
        case 'U' : flagU = 1 ; break ;
        case 'u' : if (!uid0_scan(l.arg, &uid)) dieusage() ; break ;
        case 'g' : if (!gid0_scan(l.arg, &gid)) dieusage() ; break ;
        case 'i' : ipport = l.arg ; break ;
        case 'R' : newroot = l.arg ; break ;
        case 'b' : if (!uint0_scan(l.arg, &bufsize)) dieusage() ; break ;
        case 'f' : cachelist = l.arg ; break ;
        case 'T' : ops &= ~1 ; break ;
        case 't' : ops |= 1 ; break ;
        case 'N' : ops &= ~2 ; break ;
        case 'n' : ops |= 2 ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }

  {
    int fd ;
    char ip[4] ;
    uint16_t port ;
    size_t pos = ip4_scan(ipport, ip) ;
    if (!pos) dieusage() ;
    if (ipport[pos] != ':') dieusage() ;
    if (!uint160_scan(ipport + pos + 1, &port)) dieusage() ;
    fd = socket_udp4() ;
    if (fd < 0) strerr_diefu1sys(111, "create UDP socket") ;
    if (socket_bind4_reuse(fd, ip, port) < 0)
    {
      char fmti[IP4_FMT] ;
      char fmtp[UINT16_FMT] ;
      fmti[ip4_fmt(fmti, ip)] = 0 ;
      fmtp[uint16_fmt(fmtp, port)] = 0 ;
      strerr_diefu4sys(111, "bind on ip ", fmti, " port ", fmtp) ;
    }
    if (bufsize) socket_tryreservein(fd, bufsize) ;
    if (fd_move(0, fd) < 0)
      strerr_diefu1sys(111, "move file descriptors") ;
  }

  if (newroot)
  {
    if (chdir(newroot) < 0 || chroot(".") < 0)
      strerr_diefu2sys(111, "chroot to ", newroot) ;
  }

  if (flagU)
  {
    char const *x = getenv("UID") ;
    if (x && !uid0_scan(x, &uid))
      strerr_dieinvalid(100, "UID") ;
    x = getenv("GID") ;
    if (x && !gid0_scan(x, &gid))
      strerr_dieinvalid(100, "GID") ;
  }
  if (gid != (gid_t)-1 && setgid(gid) < 0)
  {
    char fmt[GID_FMT] ;
    fmt[gid_fmt(fmt, gid)] = 0 ;
    strerr_diefu2sys(111, "setgid to ", fmt) ;
  }
  if (uid != (uid_t)-1 && setuid(uid) < 0)
  {
    char fmt[UID_FMT] ;
    fmt[uid_fmt(fmt, uid)] = 0 ;
    strerr_diefu2sys(111, "setuid to ", fmt) ;
  }

  {
    char const *newargv[10] = { "dnsfunneld" } ;
    char const *newenvp[1] = { 0 } ;
    unsigned int m = 1 ;
    char fmtv[UINT_FMT] ;
    char fmtn[UINT_FMT] ;
    char fmto[UINT_FMT] ;
    if (verbosity != 1)
    {
      fmtv[uint_fmt(fmtv, verbosity)] = 0 ;
      newargv[m++] = "-v" ;
      newargv[m++] = fmtv ;
    }
    if (notif)
    {
      fmtn[uint_fmt(fmtn, notif)] = 0 ;
      newargv[m++] = "-d" ;
      newargv[m++] = fmtn ;
    }
    if (ops)
    {
      fmto[uint_fmt(fmto, ops)] = 0 ;
      newargv[m++] = "-o" ;
      newargv[m++] = fmto ;
    }   
    newargv[m++] = "--" ;
    newargv[m++] = cachelist ;
    newargv[m++] = 0 ;
    xexec_ae(DNSFUNNEL_BINPREFIX "dnsfunneld", newargv, newenvp) ;
  }
}
