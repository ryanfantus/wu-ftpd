/****************************************************************************

  Copyright (c) 2003 WU-FTPD Development Group.
  All rights reserved.

  Use and distribution of this software and its source code are governed
  by the terms and conditions of the WU-FTPD Software License ("LICENSE").

  If you did not receive a copy of the license, it may be obtained online
  at http://www.wu-ftpd.info/license.html.

  $Id: gssutil.h,v 1.5 2011/10/20 22:58:10 wmaton Exp $

****************************************************************************/

#ifndef _GSSUTIL_H
#define	_GSSUTIL_H

#include "secutil.h"

/*
 * Strange problem when using 'gcc' compiler on a system that has more than
 * one gssapi/gssapi.h file installed (e.g. a Solaris system that also has
 * an MIT KRB5 distribution installed):
 * 'gcc' automatically looks in /usr/local/include before looking in
 * /usr/include and will end up including the gssapi.h file from the MIT
 * distribution when the original intent was to use the system gssapi.h file.
 */
#if defined(NEED_SYSTEM_GSSAPI_HEADER)
#include "/usr/include/gssapi/gssapi.h"
#else
#include <gssapi/gssapi.h>
#endif

#include <pwd.h>

#if !defined(HAVE_GSS_C_NT_HOSTBASED_SERVICE) && \
     defined(GSS_RFC_COMPLIANT_OIDS) && GSS_RFC_COMPLIANT_OIDS==0
/* We must be using MIT KRB5 1.2.X code so include the other header */
#include <gssapi/gssapi_generic.h>
#define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#endif /* !defined(HAVE_GSS_C_NT_HOSTBASED_SERVICE) ... */

#ifndef g_OID_equal
#define	g_OID_equal(o1, o2) \
	(((o1)->length == (o2)->length) && \
	(memcmp((o1)->elements, (o2)->elements, (int)(o1)->length) == 0))
#endif /* g_OID_equal */

#define	GSS_AUTH_NONE 0x00
#define	GSS_ADAT_DONE 0x01
#define	GSS_USER_DONE 0x02
#define	GSS_PWD_DONE  0x04

typedef struct gss_inforec {
	gss_ctx_id_t	context;
	gss_OID		mechoid;
	gss_name_t	client;
	char		*display_name;
	gss_buffer_desc acceptor_name;
	unsigned char	data_prot;
	unsigned char	ctrl_prot;
	unsigned char	authstate;
	unsigned char	want_creds;
	unsigned char	have_creds;
	unsigned char	must_gss_auth;
} gss_info_t;

#define	GSSUSERAUTH_OK(x) (((x).authstate & (GSS_ADAT_DONE|GSS_USER_DONE)) \
== (GSS_ADAT_DONE|GSS_USER_DONE))

int gss_user(struct passwd *);
int gss_adat(char *adatstr);
unsigned int gss_setpbsz(char *pbszstr);
int sec_write(int fd, char *buf, int len);
void ccc(void);
int sec_putc(int c, FILE *stream);
int sec_getc(FILE *stream);
int sec_fprintf(FILE *stream, char *fmt, ...);
int sec_fflush(FILE *stream);
int sec_read(int fd, char *buf, int maxlen);
int sec_reply(char *buf, int bufsiz, int n);
char *sec_decode_command(char *cmd);
size_t gss_getinbufsz(void);
void gss_adjust_buflen(void);

#endif /* _GSSUTIL_H */
