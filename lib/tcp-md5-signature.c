/*
 *	BIRD -- TCP MD5 Signature (RFC 2385)
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/tcp-md5-signature.h"

int
sk_unset_md5_auth_listening(sock *s, ip_addr local, ip_addr remote, struct iface *ifa)
{
  return sk_set_md5_auth_listening(s, local, remote, ifa, NULL);
}

int
sk_unset_md5_auth_connecting(sock *s, ip_addr local, ip_addr remote, struct iface *ifa)
{
  return sk_set_md5_auth_connecting(s, local, remote, ifa, NULL);
}

#if 0

/**
 * sk_set_md5_auth_listening - add / remove MD5 security association for given listening socket
 * @s: socket
 * @local: IP address of this side
 * @remote: IP address of the other side
 * @ifa: Interface for link-local IP address
 * @passwd: password used for MD5 authentication
 *
 * In TCP MD5 handling code in kernel, there is a set of pairs (address,
 * password) used to choose password according to address of the other side.
 * This function is useful for listening socket, for active sockets it is enough
 * to set s->password field.
 *
 * When called with passwd != NULL, the new pair is added,
 * When called with passwd == NULL, the existing pair is removed.
 *
 * Result: 0 for success, -1 for an error.
 */
int sk_set_md5_auth_listening(sock *s, ip_addr local, ip_addr remote, struct iface *ifa, char *passwd)
{
  DUMMY;
}

/**
 * sk_set_md5_auth_connecting - add / remove MD5 security association for given connecting (non-listening) socket
 * @s: socket
 * @local: IP address of this side
 * @remote: IP address of the other side
 * @ifa: Interface for link-local IP address
 * @passwd: password used for MD5 authentication
 *
 * Same as sk_set_md5_auth_listening().
 *
 * In TCP MD5 handling code in kernel, there is a set of pairs (address,
 * password) used to choose password according to address of the other side.
 * This function is useful for listening socket, for active sockets it is enough
 * to set s->password field.
 *
 * When called with passwd != NULL, the new pair is added,
 * When called with passwd == NULL, the existing pair is removed.
 *
 * Result: 0 for success, -1 for an error.
 */
int sk_set_md5_auth_connecting(sock *s, ip_addr local, ip_addr remote, struct iface *ifa, char *passwd)
{
  DUMMY;
}

#endif
