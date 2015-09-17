/*
 *	BIRD Internet Routing Daemon -- BSD Multicasting and Network Includes
 *
 *	(c) 2004       Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <net/if_dl.h>
#include <netinet/in_systm.h> // Workaround for some BSDs
#include <netinet/ip.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <err.h>
#include <net/route.h>
#include <netinet/in.h>
#include <net/pfkeyv2.h>
#include <netipsec/keydb.h>
#include <netipsec/key_debug.h>
#include <netipsec/ipsec.h>
#include <netdb.h>

#include "sysdep/config.h"
#include "nest/route.h"
#include "lib/socket.h"
#include "lib/birdlib.h"


#ifdef __NetBSD__

#ifndef IP_RECVTTL
#define IP_RECVTTL 23
#endif

#ifndef IP_MINTTL
#define IP_MINTTL 24
#endif

#endif

#ifdef __DragonFly__
#define TCP_MD5SIG	TCP_SIGNATURE_ENABLE
#endif


#define SA_LEN(x) (x).sa.sa_len


/*
 *	BSD IPv4 multicast syscalls
 */

#define INIT_MREQ4(maddr,ifa) \
  { .imr_multiaddr = ipa_to_in4(maddr), .imr_interface = ipa_to_in4(ifa->addr->ip) }

static inline int
sk_setup_multicast4(sock *s)
{
  struct in_addr ifa = ipa_to_in4(s->iface->addr->ip);
  u8 ttl = s->ttl;
  u8 n = 0;

  /* This defines where should we send _outgoing_ multicasts */
  if (setsockopt(s->fd, IPPROTO_IP, IP_MULTICAST_IF, &ifa, sizeof(ifa)) < 0)
    ERR("IP_MULTICAST_IF");

  if (setsockopt(s->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
    ERR("IP_MULTICAST_TTL");

  if (setsockopt(s->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &n, sizeof(n)) < 0)
    ERR("IP_MULTICAST_LOOP");

  return 0;
}

static inline int
sk_join_group4(sock *s, ip_addr maddr)
{
  struct ip_mreq mr = INIT_MREQ4(maddr, s->iface);

  if (setsockopt(s->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
    ERR("IP_ADD_MEMBERSHIP");

  return 0;
}

static inline int
sk_leave_group4(sock *s, ip_addr maddr)
{
  struct ip_mreq mr = INIT_MREQ4(maddr, s->iface);

  if (setsockopt(s->fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mr, sizeof(mr)) < 0)
    ERR("IP_ADD_MEMBERSHIP");

  return 0;
}


/*
 *	BSD IPv4 packet control messages
 */

/* It uses IP_RECVDSTADDR / IP_RECVIF socket options instead of IP_PKTINFO */

#define CMSG4_SPACE_PKTINFO (CMSG_SPACE(sizeof(struct in_addr)) + \
			     CMSG_SPACE(sizeof(struct sockaddr_dl)))
#define CMSG4_SPACE_TTL CMSG_SPACE(sizeof(char))

static inline int
sk_request_cmsg4_pktinfo(sock *s)
{
  int y = 1;

  if (setsockopt(s->fd, IPPROTO_IP, IP_RECVDSTADDR, &y, sizeof(y)) < 0)
    ERR("IP_RECVDSTADDR");

  if (setsockopt(s->fd, IPPROTO_IP, IP_RECVIF, &y, sizeof(y)) < 0)
    ERR("IP_RECVIF");

  return 0;
}

static inline int
sk_request_cmsg4_ttl(sock *s)
{
  int y = 1;

  if (setsockopt(s->fd, IPPROTO_IP, IP_RECVTTL, &y, sizeof(y)) < 0)
    ERR("IP_RECVTTL");

  return 0;
}

static inline void
sk_process_cmsg4_pktinfo(sock *s, struct cmsghdr *cm)
{
  if (cm->cmsg_type == IP_RECVDSTADDR)
    s->laddr = ipa_from_in4(* (struct in_addr *) CMSG_DATA(cm));

  if (cm->cmsg_type == IP_RECVIF)
    s->lifindex = ((struct sockaddr_dl *) CMSG_DATA(cm))->sdl_index;
}

static inline void
sk_process_cmsg4_ttl(sock *s, struct cmsghdr *cm)
{
  if (cm->cmsg_type == IP_RECVTTL)
    s->rcv_ttl = * (byte *) CMSG_DATA(cm);
}

static inline void
sk_prepare_cmsgs4(sock *s, struct msghdr *msg, void *cbuf, size_t cbuflen)
{
  /* Unfortunately, IP_SENDSRCADDR does not work for raw IP sockets on BSD kernels */

#ifdef IP_SENDSRCADDR
  struct cmsghdr *cm;
  struct in_addr *sa;
  int controllen = 0;

  msg->msg_control = cbuf;
  msg->msg_controllen = cbuflen;

  cm = CMSG_FIRSTHDR(msg);
  cm->cmsg_level = IPPROTO_IP;
  cm->cmsg_type = IP_SENDSRCADDR;
  cm->cmsg_len = CMSG_LEN(sizeof(*sa));
  controllen += CMSG_SPACE(sizeof(*sa));

  sa = (struct in_addr *) CMSG_DATA(cm);
  *sa = ipa_to_in4(s->saddr);

  msg->msg_controllen = controllen;
#endif
}

static void
sk_prepare_ip_header(sock *s, void *hdr, int dlen)
{
  struct ip *ip = hdr;

  bzero(ip, 20);

  ip->ip_v = 4;
  ip->ip_hl = 5;
  ip->ip_tos = (s->tos < 0) ? 0 : s->tos;
  ip->ip_len = 20 + dlen;
  ip->ip_ttl = (s->ttl < 0) ? 64 : s->ttl;
  ip->ip_p = s->dport;
  ip->ip_src = ipa_to_in4(s->saddr);
  ip->ip_dst = ipa_to_in4(s->daddr);

#ifdef __OpenBSD__
  /* OpenBSD expects ip_len in network order, other BSDs expect host order */
  ip->ip_len = htons(ip->ip_len);
#endif
}


/*
 *	Miscellaneous BSD socket syscalls
 */

#ifndef TCP_KEYLEN_MAX
#define TCP_KEYLEN_MAX 80
#endif
#ifndef TCP_SIG_SPI
#define TCP_SIG_SPI 0x1000
#endif
#ifndef BUFSIZ
#define BUFSIZ 8192
#endif

/*
 * Open a socket for manage the IPsec SA/SP database entries
 * Return:
 *	-1: fail.
 *	others: success and return value of socket.
 */
static int
sk_set_md5_password_socket_open()
{
  int so;
  const int bufsiz = BUFSIZ;

  if ((so = socket(PF_KEY, SOCK_RAW, PF_KEY_V2)) < 0)
    return -1; /* FAIL */

  /*
   * This is a temporary workaround for KAME PR 154.
   * Don't really care even if it fails.
   */
  (void)setsockopt(so, SOL_SOCKET, SO_SNDBUF, &bufsiz, sizeof(bufsiz));
  (void)setsockopt(so, SOL_SOCKET, SO_RCVBUF, &bufsiz, sizeof(bufsiz));

  return so;
}

static int
sk_set_md5_password_send(char *setkey_msg, size_t msg_len)
{
  ssize_t l;

  int so = sk_set_md5_password_socket_open();
  if (so < 0)
  {
    log(L_ERR "Cannot open socket for control TCP MD5 siganture keys in the IPsec SA/SP database: %s", strerror(errno));
    return -1; /* FAIL */
  }

  /* Need we really wait for response? */
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  if (setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
  {
    log(L_ERR "Cannot set setsockopt() at socket for control TCP MD5 siganture keys in the IPsec SA/SP database: %s", strerror(errno));
    close(so);
    return -1; /* FAIL */
  }

  if ((l = send(so, setkey_msg, msg_len, 0)) < 0)
  {
    log(L_ERR "Cannot send a control command to the IPsec SA/SP database: %s", strerror(errno));
    close(so);
    return -1; /* FAIL */
  }

  close(so);
  return 0; /* OK */
}

static int
sk_set_md5_password_setvarbuf(char *buf, int *off, struct sadb_ext *ebuf, int elen, caddr_t vbuf, int vlen)
{
  memset(buf + *off, 0, PFKEY_UNUNIT64(ebuf->sadb_ext_len));
  memcpy(buf + *off, (caddr_t)ebuf, elen);
  memcpy(buf + *off + elen, vbuf, vlen);
  (*off) += PFKEY_ALIGN8(elen + vlen);

  return 0;
}

#define SADB_OVERWRITE 25
/*
 * Perform setkey(8)-like operation for set the password for TCP MD5 Signature (RFC 2385)
 * If type == SADB_OVERWRITE then it attempts to perform sequentially two operations:
 * 	1) operation SADB_DELETE
 * 	2) operation SADB_ADD
 */
static int
sk_set_md5_password_prepare(sockaddr *srcs, sockaddr *dsts, char *passwd, uint type)
{
  if (!srcs || !dsts)
    return -1;

  char buf[BUFSIZ] = {};
  struct sadb_msg *msg;
  struct sadb_key *m_key;
  struct sadb_sa *m_sa;
  struct sadb_x_sa2 *m_sa2;
  struct sadb_address m_addr = {};
  struct sockaddr *sa;
  int l, len, prefix_len, salen;

  uint passwd_len = passwd ? strlen(passwd) : 0;

  size_t estimate_total_size =
        sizeof(struct sadb_msg)
      + sizeof(struct sadb_key)
      + PFKEY_ALIGN8(passwd_len)
      + sizeof(struct sadb_sa)
      + sizeof(struct sadb_x_sa2)
      + PFKEY_ALIGN8(sizeof(struct sadb_address) + srcs->sa.sa_len)
      + PFKEY_ALIGN8(sizeof(struct sadb_address) + dsts->sa.sa_len);
  if (estimate_total_size > sizeof(buf))
  {
    log(L_ERR "Setting the TCP MD5 siganture key to the IPsec SA/SP database failed: buffer of size %zu bytes is too small, "
	      "we need at least %zu bytes", sizeof(buf), estimate_total_size);
    return -1;
  }

  msg = (struct sadb_msg *) buf;
  l = sizeof(struct sadb_msg);
  msg->sadb_msg_version = PF_KEY_V2;
  msg->sadb_msg_type = type;
  msg->sadb_msg_satype = SADB_X_SATYPE_TCPSIGNATURE;
  msg->sadb_msg_pid = getpid();
  /* fix up msg->sadb_msg_len afterwards */

  /* set authentication algorithm and password */
  m_key = (struct sadb_key *)(buf + l);
  len = sizeof(struct sadb_key);
  m_key->sadb_key_len = PFKEY_UNIT64(len + PFKEY_ALIGN8(passwd_len));
  m_key->sadb_key_exttype = SADB_EXT_KEY_AUTH;
  m_key->sadb_key_bits = passwd_len * 8;
  l += len;
  memcpy(buf + l, passwd, passwd_len);
  l += PFKEY_ALIGN8(passwd_len);

  m_sa = (struct sadb_sa *)(buf + l);
  len = sizeof(struct sadb_sa);
  m_sa->sadb_sa_len = PFKEY_UNIT64(len);
  m_sa->sadb_sa_exttype = SADB_EXT_SA;
  m_sa->sadb_sa_spi = htonl((u32) TCP_SIG_SPI);
  m_sa->sadb_sa_auth = SADB_X_AALG_TCP_MD5;
  m_sa->sadb_sa_encrypt = SADB_EALG_NONE;
  m_sa->sadb_sa_flags = SADB_X_EXT_CYCSEQ;
  l += len;

  m_sa2 = (struct sadb_x_sa2 *)(buf + l);
  len = sizeof(struct sadb_x_sa2);
  m_sa2->sadb_x_sa2_len = PFKEY_UNIT64(len);
  m_sa2->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
  m_sa2->sadb_x_sa2_mode = IPSEC_MODE_ANY;
  l += len;

#ifdef IPV6
  prefix_len = sizeof(struct in6_addr) << 3;
#else
  prefix_len = sizeof(struct in_addr) << 3;
#endif

  /* set source address */
  sa = &srcs->sa;
  salen = srcs->sa.sa_len;
  m_addr.sadb_address_len = PFKEY_UNIT64(sizeof(m_addr) + PFKEY_ALIGN8(salen));
  m_addr.sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
  m_addr.sadb_address_proto = IPSEC_ULPROTO_ANY;
  m_addr.sadb_address_prefixlen = prefix_len;
  sk_set_md5_password_setvarbuf(buf, &l, (struct sadb_ext *)&m_addr, sizeof(m_addr), (caddr_t)sa, salen);

  /* set destination address */
  sa = &dsts->sa;
  salen = dsts->sa.sa_len;
  m_addr.sadb_address_len = PFKEY_UNIT64(sizeof(m_addr) + PFKEY_ALIGN8(salen));
  m_addr.sadb_address_exttype = SADB_EXT_ADDRESS_DST;
  m_addr.sadb_address_proto = IPSEC_ULPROTO_ANY;
  m_addr.sadb_address_prefixlen = prefix_len;
  sk_set_md5_password_setvarbuf(buf, &l, (struct sadb_ext *)&m_addr, sizeof(m_addr), (caddr_t)sa, salen);

  msg->sadb_msg_len = PFKEY_UNIT64(l);

  if (type == SADB_OVERWRITE)
  {
    /* delete possible current key in the IPsec SA/SP database */
    msg->sadb_msg_type = SADB_DELETE;
    sk_set_md5_password_send(buf, l);
    msg->sadb_msg_type = SADB_ADD;
  }

  return sk_set_md5_password_send(buf, l);
}

static int
sk_set_md5_password(sock *s, ip_addr local, ip_addr remote, struct iface *ifa, char *passwd, int type)
{
  sockaddr src = {};
  sockaddr dst = {};
  sockaddr_fill(&src, s->af, local, ifa, 0);
  sockaddr_fill(&dst, s->af, remote, ifa, 0);
  return sk_set_md5_password_prepare(&src, &dst, passwd, type);
}

static int
sk_set_md5_auth(sock *s, char *passwd)
{
  int enable = 0;

  if (passwd && *passwd)
  {
    enable = TCP_SIG_SPI;

    int len = strlen(passwd);

    if (len > TCP_KEYLEN_MAX)
      ERR_MSG("The password for TCP MD5 Signature is too long");
  }

  if (setsockopt(s->fd, IPPROTO_TCP, TCP_MD5SIG, &enable, sizeof(enable)) < 0)
  {
    if (errno == ENOPROTOOPT)
      ERR_MSG("Kernel does not support TCP MD5 signatures");
    else
      ERR("TCP_MD5SIG");
  }

  return 0;
}

/* Manipulation with the IPsec SA/SP database */
static int
sk_set_md5_in_sasp_db(sock *s, ip_addr local, ip_addr remote, struct iface *ifa, char *passwd)
{
  if (passwd && *passwd)
  {
    int len = strlen(passwd);
    if (len > TCP_KEYLEN_MAX)
      ERR_MSG("The password for TCP MD5 Signature is too long");

    /* At BSD systems is necessary to handle password via the IPsec SA/SP database.
     * Checkout manual page tcp(4) and search TCP_MD5SIG at FreeBSD */
    if (sk_set_md5_password(s, local, remote, ifa, passwd, SADB_OVERWRITE) < 0)
      ERR_MSG("Cannot add a TCP-MD5 password into the IPsec SA/SP database.");
  }
  else
  {
    if (sk_set_md5_password(s, local, remote, ifa, NULL, SADB_DELETE) < 0)
      ERR_MSG("Cannot delete a TCP-MD5 password from the IPsec SA/SP database.");
  }
  return 0;
}

int
sk_set_md5_auth_listening(sock *s, ip_addr local, ip_addr remote, struct iface *ifa, char *passwd)
{
  return sk_set_md5_in_sasp_db(s, local, remote, ifa, passwd);
}

int
sk_set_md5_auth_connecting(sock *s, ip_addr local, ip_addr remote, struct iface *ifa, char *passwd)
{
  return sk_set_md5_auth(s, passwd);
}

static inline int
sk_set_min_ttl4(sock *s, int ttl)
{
  if (setsockopt(s->fd, IPPROTO_IP, IP_MINTTL, &ttl, sizeof(ttl)) < 0)
  {
    if (errno == ENOPROTOOPT)
      ERR_MSG("Kernel does not support IPv4 TTL security");
    else
      ERR("IP_MINTTL");
  }

  return 0;
}

static inline int
sk_set_min_ttl6(sock *s, int ttl)
{
  ERR_MSG("Kernel does not support IPv6 TTL security");
}

static inline int
sk_disable_mtu_disc4(sock *s)
{
  /* TODO: Set IP_DONTFRAG to 0 ? */
  return 0;
}

static inline int
sk_disable_mtu_disc6(sock *s)
{
  /* TODO: Set IPV6_DONTFRAG to 0 ? */
  return 0;
}

int sk_priority_control = -1;

static inline int
sk_set_priority(sock *s, int prio UNUSED)
{
  ERR_MSG("Socket priority not supported");
}
