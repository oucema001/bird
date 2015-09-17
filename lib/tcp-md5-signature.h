/*
 *	BIRD -- TCP MD5 Signature (RFC 2385)
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_TCP_MD5_SIGNATURE_H_
#define _BIRD_TCP_MD5_SIGNATURE_H_

#include "lib/socket.h"
#include "lib/ip.h"

#ifndef TCP_MD5SIG

#define TCP_MD5SIG  14
#define TCP_MD5SIG_MAXKEYLEN 80

struct tcp_md5sig {
  struct  sockaddr_storage tcpm_addr;             /* address associated */
  u16   __tcpm_pad1;                              /* zero */
  u16   tcpm_keylen;                              /* key length */
  u32   __tcpm_pad2;                              /* zero */
  u8    tcpm_key[TCP_MD5SIG_MAXKEYLEN];           /* key (binary) */
};

#endif

int sk_set_md5_auth_listening(sock *s, ip_addr local, ip_addr remote, struct iface *ifa, char *passwd);
int sk_set_md5_auth_connecting(sock *s, ip_addr local, ip_addr remote, struct iface *ifa, char *passwd);

int sk_unset_md5_auth_listening(sock *s, ip_addr local, ip_addr remote, struct iface *ifa);
int sk_unset_md5_auth_connecting(sock *s, ip_addr local, ip_addr remote, struct iface *ifa);

#endif /* _BIRD_TCP_MD5_SIGNATURE_H_ */
