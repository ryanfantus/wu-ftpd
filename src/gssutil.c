/****************************************************************************

  Copyright (c) 2003 WU-FTPD Development Group.
  All rights reserved.

  Use and distribution of this software and its source code are governed
  by the terms and conditions of the WU-FTPD Software License ("LICENSE").

  If you did not receive a copy of the license, it may be obtained online
  at http://www.wu-ftpd.info/license.html.

  $Id: gssutil.c,v 1.7 2012/01/07 23:23:57 wmaton Exp $

****************************************************************************/

/*
 * gssutil.c
 *
 * Utility routines for providing security related services to the FTP server.
 * This code uses the GSSAPI (RFC 2743, 2744) to provide a generic security
 * layer to the application.  The security mechanism providing the actual
 * security functions is abstracted from the application itself.  In the case
 * of the FTP server, the security mechanism is based on what the client
 * chooses to use when it makes the secure connection.  If the client's choice
 * of GSS mechanism is not supported by the FTP server, the connection may be
 * rejected or fall back to standard Unix/PAM authentication.
 *
 * This code is primarily intended to work with clients who choose the Kerberos
 * V5 GSSAPI mechanism as their security service.
 */

#include "config.h"

#if defined(USE_GSS)
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <signal.h>
#include <stdarg.h>
#include <pwd.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <errno.h>
#include <sys/param.h>
#include <netdb.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif

#if defined(OTHER_PASSWD)
#include "getpwnam.h"
extern char _path_passwd[];
#endif /* defined(OTHER_PASSWD) */

#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif

#ifdef HAVE_SYSINFO
#include <sys/systeminfo.h>
#endif

#include "tls_port.h"
#include "gssutil.h"
#include "proto.h"
#include "ftp.h"

static char *gss_services[] = { "ftp", "host", 0 };

gss_info_t gss_info = {
    /* context */ GSS_C_NO_CONTEXT,
    /* mechoid */ GSS_C_NULL_OID,
    /* client */ NULL,
    /* display_name */ NULL,
    /* acceptor_name */ {NULL, 0},
    /* data_prot */  PROT_C,
    /* ctrl_prot */  PROT_C,
    /* authstate */  GSS_AUTH_NONE,
    /* want_creds */ 0,
    /* have_creds */ 0,
    /* must_auth  */ 0
};

extern struct SOCKSTORAGE his_addr;
extern struct SOCKSTORAGE ctrl_addr;
extern int debug;

static char *radixN =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char pad = '=';

#define	DEF_GSSBUF_SIZE 2028

typedef struct {
    char   *buf;
    size_t alloc_len;
    size_t len;  /* max length of buffer */
    size_t idx;  /* offset to beginning of read/write data */
    size_t clen;  /* length of the remaining, decrypted data from client */
}bufrec;

static bufrec obr = {NULL, 0, 0, 0, 0};
static bufrec ibr = {NULL, 0, 0, 0, 0};

static int looping_write(int fd, const char *buf, size_t len);
static int looping_read(int fd, char *buf, size_t len);
static int radix_encode(unsigned char *inbuf, unsigned char *outbuf,
	    int *len, int decode);
static char *radix_error(int e);
static void reply_gss_error(int code, OM_uint32 maj_stat,
		OM_uint32 min_stat, gss_OID mechoid, char *s);
static void cleanup_bufrec(bufrec *brec);
static int alloc_bufrec(bufrec *brec, size_t newsz);
static int sec_putbuf(int fd, unsigned char *buf, int len);
static int sec_getbytes(int fd, char *buf, int nbytes);

/*
 * Provide a routine so that ftpd can know the max amount to read
 */
size_t
gss_getinbufsz(void) {
    return (ibr.len);
}

/*
 * gss_adjust_buflen
 *
 * Called when the protection method changes so we can adjust the
 * "useable" length of our output buffer accordingly.
 */
void
gss_adjust_buflen()
{
    OM_uint32 maj_stat, min_stat, mlen;

    /*
     * If we switched to CLEAR protection, we can use the entire buffer
     */
    if (gss_info.data_prot == PROT_C) {
	obr.len = obr.alloc_len;
	return;
    }

    /*
     * Otherwise, determine the maximum size that will allow for
     * the GSSAPI overhead to fit into the buffer size.
     */
    maj_stat = gss_wrap_size_limit(&min_stat, gss_info.context,
		    (gss_info.data_prot == PROT_P), GSS_C_QOP_DEFAULT,
		    (OM_uint32)obr.alloc_len, &mlen);
    if (maj_stat != GSS_S_COMPLETE) {
	reply_gss_error(535, maj_stat, min_stat, gss_info.mechoid,
	    "GSSAPI fudge determination");
	return;
    }
    obr.len = mlen;
    if (debug)
	syslog(LOG_DEBUG,
	    "GSSAPI alloc_len = %d len = %d", obr.alloc_len, obr.len);
}

static int
looping_write(int fd, const char *buf, size_t len)
{
    int cc;
    register size_t wrlen = len;

    do {
	cc = WRITE(fd, buf, wrlen);
	if (cc < 0) {
	    if (errno == EINTR)
		continue;
	    return (cc);
	} else {
	    buf += cc;
	    wrlen -= cc;
	}
    } while (wrlen > 0);

    return (len);
}

static int
looping_read(int fd, char *buf, size_t len)
{
    int cc;
    size_t len2 = 0;

    do {
	cc = READ(fd, buf, len);
	if (cc < 0) {
	    if (errno == EINTR)
		continue;
	    return (cc);		 /* errno is already set */
	} else if (cc == 0) {
	    return (len2);
	} else {
	    buf += cc;
	    len2 += cc;
	    len -= cc;
	}
    } while (len > 0);
    return (len2);
}

static int
radix_encode(unsigned char *inbuf, unsigned char *outbuf, int *len, int decode)
{
    register int i, j, D;
    char *p;
    unsigned char c;

    if (decode) {
	for (i = 0, j = 0; inbuf[i] && inbuf[i] != pad; i++) {
	    if ((p = strchr(radixN, inbuf[i])) == NULL)
		return (1);
	    D = p - radixN;
	    switch (i&3) {
	    case 0:
		outbuf[j] = D <<2;
		break;
	    case 1:
		outbuf[j++] |= D >>4;
		outbuf[j] = (D&15)<<4;
		break;
	    case 2:
		outbuf[j++] |= D >>2;
		outbuf[j] = (D&3)<<6;
		break;
	    case 3:
		outbuf[j++] |= D;
	    }
	}
	switch (i&3) {
	case 1:
	    return (3);
	case 2: if (D&15)
		return (3);
	    if (strcmp((char *)&inbuf[i], "=="))
		return (2);
	    break;
	case 3: if (D&3)
		return (3);
	    if (strcmp((char *)&inbuf[i], "="))
		return (2);
	}
	*len = j;
    } else {
	for (i = 0, j = 0; i < *len; i++)
	    switch (i%3) {
	    case 0:
		outbuf[j++] = radixN[inbuf[i]>>2];
		c = (inbuf[i]&3)<<4;
		break;
	    case 1:
		outbuf[j++] = radixN[c|inbuf[i]>>4];
		c = (inbuf[i]&15)<<2;
		break;
	    case 2:
		outbuf[j++] = radixN[c|inbuf[i]>>6];
		outbuf[j++] = radixN[inbuf[i]&63];
		c = 0;
	}
	if (i%3) outbuf[j++] = radixN[c];
	switch (i%3) {
	case 1: outbuf[j++] = pad;
	case 2: outbuf[j++] = pad;
	}
	outbuf[*len = j] = '\0';
    }
    return (0);
}

static char *
radix_error(int e)
{
    switch (e) {
	case 0:  return ("Success");
	case 1:  return ("Bad character in encoding");
	case 2:  return ("Encoding not properly padded");
	case 3:  return ("Decoded # of bits not a multiple of 8");
	default: return ("Unknown error");
    }
}

static void
reply_gss_error(int code, OM_uint32 maj_stat,
    OM_uint32 min_stat, gss_OID mechoid, char *s)
{
    /* a lot of work just to report the error */
    OM_uint32 gmaj_stat, gmin_stat;
    gss_buffer_desc msg;
    int msg_ctx;
    msg_ctx = 0;

    gmaj_stat = gss_display_status(&gmin_stat, maj_stat, GSS_C_GSS_CODE,
		    mechoid, (OM_uint32 *)&msg_ctx, &msg);
    if (gmaj_stat == GSS_S_COMPLETE) {
	lreply(code, "GSSAPI error major: %s", (char *)msg.value);
	(void) gss_release_buffer(&gmin_stat, &msg);
    }

    gmaj_stat = gss_display_status(&gmin_stat, min_stat, GSS_C_MECH_CODE,
		    mechoid, (OM_uint32 *)&msg_ctx, &msg);
    if (gmaj_stat == GSS_S_COMPLETE) {
	lreply(code, "GSSAPI error minor: %s", (char *)msg.value);
	(void) gss_release_buffer(&gmin_stat, &msg);
    }

    reply(code, "GSSAPI error: %s", s);
}

/*
 * gss_user
 *
 * Handle USER command after AUTH GSSAPI
 *
 * Perform primitive mapping between the GSS Credential and local user account.
 * A big assumption is made here:
 *   The GSS Cred "display name" is of the form:  username[/instance][@REALM]
 *    which is the Kerberos V5 principal format.  This assumption is valid
 *    until more GSS mechanisms come into play (NTLM anyone?).
 *
 * This method does not break the GSSAPI abstraction layer and make direct
 * Kerberos function calls (e.g. krb5_kuserok) as that is not portable on all
 * platforms and not everyone (Solaris) exposes the Kerberos API for public
 * use.
 *
 * return 0 == BAD, password is required.
 *        1 == OK,  no password required.
 *
 * Find the calls to 'gss_user' in ftpd.c for how this affects
 * the login process.
 */
int
gss_user(struct passwd *user_pw)
{
    int retval = 0;
    char *pname = NULL;
    char *atptr = NULL;
    char *slashptr = NULL;
    char *name;
    char  *realm = NULL;
    char  *arealm = NULL;
    struct passwd *lpw;
#if defined(M_UNIX)
    struct passwd *ret = (struct passwd *) NULL;
#endif /* defined(M_UNIX) */
#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
    struct pr_passwd *pr;
#endif /* defined(SecureWare) || defined(HPUX_10_TRUSTED) */

    if (gss_info.display_name) {
	name = gss_info.display_name;
	/*
	 * Kerberos V5 principal names look like this:
	 * principal/instance@REALM
	 *  - the "/instance" part is optional.
	 */
	atptr = strrchr(gss_info.display_name, '@');
	if (atptr) {
	    *atptr = '\0';
	    realm = atptr+1;
	}
	/*
	 * Make sure the realm of the client matches the
	 * realm of the server.	 This presumes a Kerberos-like
	 * credential string.
	 */
	if (realm != NULL &&
	    gss_info.acceptor_name.value != NULL &&
	    (arealm = strrchr(gss_info.acceptor_name.value, '@')) != NULL) {
	    arealm++;
	    if (strcmp(arealm, realm))
		goto DONE;
	}

	slashptr = strrchr(gss_info.display_name, '/');
	if (slashptr)
	    *slashptr = '\0';

#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
	if ((pr = getprpwnam(name)) == NULL)
	    goto DONE;
#endif /* defined(SecureWare) || defined(HPUX_10_TRUSTED) */
#if defined(OTHER_PASSWD)
	if ((lpw = bero_getpwnam(name, _path_passwd)) == NULL)
#else /* !(defined(OTHER_PASSWD)) */
	if ((lpw = getpwnam(name)) == NULL)
#endif /* !(defined(OTHER_PASSWD)) */
	    goto DONE;
	/*
	 * return success only if the UID of the mapped principal
	 * matches the UID of the indicated login account.
	 */
	retval = (lpw->pw_uid == user_pw->pw_uid);
    }

DONE:
    /*
     * Restore the "display_name" to its original form
     * before returning.
     */
    if (atptr)
	*atptr = '@';
    if (slashptr)
	*slashptr = '/';
    return (retval);
}

#if !defined(HAVE_GSS_GET_MECH_TYPE)
OM_uint32
__gss_get_mech_type(gss_OID OID, const gss_buffer_t token)
{
    unsigned char * buffer_ptr;
    int length;

    /*
     * This routine reads the prefix of "token" in order to determine
     * its mechanism type. It assumes the encoding suggested in
     * Appendix B of RFC 1508. This format starts out as follows :
     *
     * tag for APPLICATION 0, Sequence[constructed, definite length]
     * length of remainder of token
     * tag of OBJECT IDENTIFIER
     * length of mechanism OID
     * encoding of mechanism OID
     * <the rest of the token>
     *
     * Numerically, this looks like :
     *
     * 0x60
     * <length> - could be multiple bytes
     * 0x06
     * <length> - assume only one byte, hence OID length < 127
     * <mech OID bytes>
     *
     * The routine fills in the OID value and returns an error as necessary.
     */
    if (OID == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    if ((token == NULL) || (token->value == NULL))
	return (GSS_S_DEFECTIVE_TOKEN);

    /* Skip past the APP/Sequnce byte and the token length */

    buffer_ptr = (unsigned char *) token->value;

    if (*(buffer_ptr++) != 0x60)
	return (GSS_S_DEFECTIVE_TOKEN);
    length = *buffer_ptr++;

    /* check if token length is null */
    if (length == 0)
	return (GSS_S_DEFECTIVE_TOKEN);

    if (length & 0x80) {
	if ((length & 0x7f) > 4)
	    return (GSS_S_DEFECTIVE_TOKEN);
	buffer_ptr += length & 0x7f;
    }

    if (*(buffer_ptr++) != 0x06)
	return (GSS_S_DEFECTIVE_TOKEN);

    OID->length = (OM_uint32) *(buffer_ptr++);
    OID->elements = (void *) buffer_ptr;
    return (GSS_S_COMPLETE);
}
#endif /* !defined(HAVE_GSS_GET_MECH_TYPE) */

/*
 * gss_adat
 *
 * Handle ADAT(Authentication Data) command data.
 */
int
gss_adat(char *adatstr)
{
    int kerror, length;
    int replied = 0;
    int found = 0;
    int ret_flags;
    gss_buffer_desc name_buf, tok, out_tok;
    gss_cred_id_t server_creds;
    gss_cred_id_t deleg_creds = NULL;
    gss_name_t server_name, sname;
    OM_uint32 acquire_maj, acquire_min;
    OM_uint32 accept_maj, accept_min;
    OM_uint32 stat_maj, stat_min;
    gss_OID_desc input_token_mech_desc;
    gss_OID input_token_mechoid = &input_token_mech_desc;
    gss_OID_set_desc desiredMechs;
    gss_OID_set smechs;
    gss_OID oidval;
    char *mechstr;
    char gbuf[2*BUFSIZ];
    unsigned char gout_buf[2*BUFSIZ];
    char localname[MAXHOSTNAMELEN];
    char service_name[MAXHOSTNAMELEN+10];
    char **service;
    char *hp;

    if ((kerror = radix_encode((unsigned char *)adatstr,
		(unsigned char *)gout_buf,
		&length, 1))) {
	reply(501, "Couldn't decode ADAT(%s)", radix_error(kerror));
	syslog(LOG_ERR, "Couldn't decode ADAT(%s)", radix_error(kerror));
	return (0);
    }
    tok.value = gout_buf;
    tok.length = length;

#ifdef HAVE_SYSINFO
    if (sysinfo(SI_HOSTNAME, localname, sizeof (localname)) < 0) {
	syslog(LOG_ERR, "Couldn't get local hostname(%d)", errno);
	reply(501, "couldn't get local hostname\n");
#else
    if (gethostname(localname, sizeof (localname)) < 0) {
	syslog(LOG_ERR, "Couldn't get local hostname(%d)", errno);
	reply(501, "couldn't get local hostname\n");
#endif
    }

    if (!(hp = wu_gethostbyname(localname))) {
	reply(501, "couldn't canonicalize local hostname\n");
	syslog(LOG_ERR, "Couldn't canonicalize local hostname");
	return (0);
    }

    /*
     * Get the Correct GSS mechanism OID from the input token.
     */
    if (__gss_get_mech_type(input_token_mechoid, &tok)) {
	syslog(LOG_ERR, "Cannot determine GSS Mechanism OID from input token");
	return (0);
    }

    desiredMechs.count = 1;
    desiredMechs.elements = input_token_mechoid;

    strlcpy(localname, hp, sizeof (localname) - 1);

    for (service = gss_services; *service; service++) {
	snprintf(service_name, sizeof (service_name),
	    "%s@%s", *service, localname);

	name_buf.value = service_name;
	name_buf.length = strlen(name_buf.value) + 1;
	if (debug)
	    syslog(LOG_DEBUG, "importing <%s>", service_name);

	stat_maj = gss_import_name(&stat_min, &name_buf,
		    (gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
		    &server_name);

	if (stat_maj != GSS_S_COMPLETE) {
	    reply_gss_error(501, stat_maj, stat_min,
		    input_token_mechoid, "importing name");
	    syslog(LOG_ERR, "gssapi error importing name");
	    return (0);
	}

	acquire_maj = gss_acquire_cred(&acquire_min, server_name, 0,
				&desiredMechs, GSS_C_ACCEPT,
				&server_creds, NULL, NULL);
	(void) gss_release_name(&stat_min, &server_name);

	if (acquire_maj != GSS_S_COMPLETE)
	    continue;


	stat_maj = gss_inquire_cred(&stat_min, server_creds,
		    &sname, NULL, NULL, &smechs);
	if (stat_maj == GSS_S_COMPLETE) {
	    stat_maj = gss_display_name(&stat_min, sname,
		    &gss_info.acceptor_name,
		     &oidval);
	}
	if (stat_maj == GSS_S_COMPLETE) {
	    if (debug)
		syslog(LOG_DEBUG, "trying service name: %.*s\n",
		    (int)gss_info.acceptor_name.length,
		    (char *)gss_info.acceptor_name.value);
	    (void) gss_release_name(&stat_min, &sname);
	}
	found++;

	gss_info.context = GSS_C_NO_CONTEXT;
	accept_maj = gss_accept_sec_context(&accept_min,
			&gss_info.context,
			server_creds,
			&tok, /* ADAT data */
			GSS_C_NO_CHANNEL_BINDINGS,
			&gss_info.client,
			&gss_info.mechoid,
			&out_tok, /* output_token */
			(unsigned int *)&ret_flags,
			NULL, /* ignore time_rec */
			NULL); /* delegated creds */
	if (debug) {
	    if (accept_maj == GSS_S_COMPLETE)
		syslog(LOG_ERR,
		    "accept_maj = GSS_S_COMPLETE");
	    else if (accept_maj == GSS_S_CONTINUE_NEEDED)
		syslog(LOG_ERR,
		    "accept_maj = GSS_S_CONTINUE_NEEDED");
	}

	if (accept_maj == GSS_S_COMPLETE ||
	    accept_maj == GSS_S_CONTINUE_NEEDED)
	    break;
	else {
	    reply_gss_error(535, accept_maj, accept_min,
		input_token_mechoid, "accepting context");
	}
    }
    if (found) {
	if (accept_maj != GSS_S_COMPLETE &&
	    accept_maj != GSS_S_CONTINUE_NEEDED) {
	    reply_gss_error(535, accept_maj, accept_min,
		input_token_mechoid, "accepting context");
	    syslog(LOG_ERR, "failed accepting context");
	    (void) gss_release_cred(&stat_min, &server_creds);

	    if ((ret_flags & GSS_C_DELEG_FLAG) && deleg_creds != NULL)
		(void) gss_release_cred(&stat_min,
			    &deleg_creds);

	    if (gss_info.acceptor_name.value != NULL)
		(void) gss_release_buffer(&stat_min,
			&gss_info.acceptor_name);
	    return (0);
	}
    } else {
	/*
	 * Kludge to make sure the right error gets reported,
	 * so we don't get those nasty "error: no error" messages.
	 */
	if (stat_maj != GSS_S_COMPLETE)
	    reply_gss_error(501, stat_maj, stat_min,
		    input_token_mechoid,
		    "acquiring credentials");
	else
	    reply_gss_error(501, acquire_maj, acquire_min,
		    input_token_mechoid,
		    "acquiring credentials");

	syslog(LOG_ERR, "gssapi error acquiring credentials");
	if (gss_info.acceptor_name.value != NULL)
	    (void) gss_release_buffer(&stat_min, &gss_info.acceptor_name);
	return (0);
    }
    if (out_tok.length) {
	if ((kerror = radix_encode(out_tok.value, (unsigned char *)gbuf,
		    (int *)&out_tok.length, 0))) {
	    reply(535, "Couldn't encode ADAT reply(%s)", radix_error(kerror));
	    syslog(LOG_ERR, "couldn't encode ADAT reply");
	    (void) gss_release_cred(&stat_min, &server_creds);
	    if ((ret_flags & GSS_C_DELEG_FLAG) && deleg_creds != NULL)
		(void) gss_release_cred(&stat_min, &deleg_creds);

	    if (gss_info.acceptor_name.value != NULL)
		(void) gss_release_buffer(&stat_min, &gss_info.acceptor_name);
	    return (0);
	}
	if (stat_maj == GSS_S_COMPLETE) {
	    reply(235, "ADAT=%s", gbuf);
	    replied = 1;

	} else {
	    /*
	     * If the server accepts the security data, and requires
	     * additional data, it should respond with reply code 335.
	     */
	    reply(335, "ADAT=%s", gbuf);
	}
	(void) gss_release_buffer(&stat_min, &out_tok);
    }
    if (stat_maj == GSS_S_COMPLETE) {
	gss_buffer_desc namebuf;
	gss_OID out_oid;

	/* GSSAPI authentication succeeded */
	gss_info.authstate = GSS_ADAT_DONE;
	(void) alloc_bufrec(&obr, DEF_GSSBUF_SIZE);
	(void) alloc_bufrec(&ibr, DEF_GSSBUF_SIZE);
	/*
	 * RFC 2228 - "..., once a security data exchange completes
	 * successfully, if the security mechanism supports
	 * integrity, then integrity(via the MIC or ENC command,
	 * and 631 or 632 reply) must be used, ..."
	 */
	gss_info.ctrl_prot = PROT_S;

	stat_maj = gss_display_name(&stat_min, gss_info.client,
			&namebuf, &out_oid);
	if (stat_maj != GSS_S_COMPLETE) {
	    gss_info.authstate &= ~GSS_ADAT_DONE;
	    /*
	     * RFC 2228 - "If the server rejects the security data
	     * (if a checksum fails, for instance), it should respond
	     * with reply code 535."
	     */
	    reply_gss_error(535, stat_maj, stat_min, input_token_mechoid,
		"extracting GSSAPI identity name");
	    syslog(LOG_ERR, "gssapi error extracting identity");
	    (void) gss_release_cred(&stat_min, &server_creds);
	    if ((ret_flags & GSS_C_DELEG_FLAG) &&
		deleg_creds != NULL)
		(void) gss_release_cred(&stat_min, &deleg_creds);
	    if (gss_info.acceptor_name.value != NULL)
		(void) gss_release_buffer(&stat_min, &gss_info.acceptor_name);
	    return (0);
	}
	gss_info.display_name = (char *)namebuf.value;

	(void) gss_release_cred(&stat_min, &server_creds);

	if (ret_flags & GSS_C_DELEG_FLAG) {
	    gss_info.have_creds = 1;
	    if (deleg_creds != NULL)
		(void) gss_release_cred(&stat_min, &deleg_creds);
	}

	/*
	 * If the server accepts the security data, but does not require any
	 * additional data(i.e., the security data exchange has completed
	 * successfully), it must respond with reply code 235.
	 */
	if (!replied) {
	    if ((ret_flags & GSS_C_DELEG_FLAG) && !gss_info.have_creds)
		reply(235, "GSSAPI Authentication succeeded, but could not "
		    "accept forwarded credentials");
	    else
		reply(235, "GSSAPI Authentication succeeded");
	}
	return (1);
    } else if (stat_maj == GSS_S_CONTINUE_NEEDED) {
	/*
	 * If the server accepts the security data, and requires
	 * additional data, it should respond with reply code 335.
	 */
	reply(335, "more data needed");
	(void) gss_release_cred(&stat_min, &server_creds);
	if ((ret_flags & GSS_C_DELEG_FLAG) && deleg_creds != NULL)
	    (void) gss_release_cred(&stat_min, &deleg_creds);
    } else {
	/*
	 * "If the server rejects the security data (if a checksum fails,
	 * for instance), it should respond with reply code 535."
	 */
	reply_gss_error(535, stat_maj, stat_min, input_token_mechoid,
		"GSSAPI failed processing ADAT");
	syslog(LOG_ERR, "GSSAPI failed processing ADAT");
	(void) gss_release_cred(&stat_min, &server_creds);
	if ((ret_flags & GSS_C_DELEG_FLAG) && deleg_creds != NULL)
	    (void) gss_release_cred(&stat_min, &deleg_creds);
	if (gss_info.acceptor_name.value != NULL)
	    (void) gss_release_buffer(&stat_min, &gss_info.acceptor_name);
    }
    return (0);
}

/*
 * cleanup_bufrec
 *
 * cleanup the secure buffers
 */
static void
cleanup_bufrec(bufrec *brec)
{
    if (brec->buf)
	free(brec->buf);
    brec->len = 0;
    brec->clen = 0;
    brec->idx = 0;
}

static int
alloc_bufrec(bufrec *brec, size_t newsz)
{
    /*
     * Try to allocate a buffer, if it fails,
     * divide by 2 and try again.
     */
    cleanup_bufrec(brec);

    while (newsz > 0 && !(brec->buf = malloc(newsz))) {
	syslog(LOG_ERR, "malloc bufrec(%d bytes) failed, trying %d",
	    newsz >>= 1);
    }

    if (brec->buf == NULL)
	return (-1);

    brec->alloc_len = newsz;
    brec->len = newsz;
    brec->clen = 0;
    brec->idx = 0;
    return (0);
}

/*
 * Handle PBSZ command data, return value to caller.
 * RFC 2228 says this is a 32 bit int, so limit max value here.
 */
unsigned int
gss_setpbsz(char *pbszstr)
{
    unsigned int newsz = 0;
    char *endp;
#define	MAX_PBSZ 4294967295u

    errno = 0;
    newsz = (unsigned int)strtol(pbszstr, &endp, 10);
    if (errno != 0 || newsz > MAX_PBSZ || *endp != '\0') {
	reply(501, "Bad value for PBSZ: %s", pbszstr);
	return (0);
    }

    if (newsz > ibr.len) {
	if (alloc_bufrec(&obr, newsz) == -1) {
	    perror_reply(421, "Local resource failure: malloc");
	    dologout(1);
	}
	if (alloc_bufrec(&ibr, newsz) == -1) {
	    perror_reply(421, "Local resource failure: malloc");
	    dologout(1);
	}
    }
    reply(200, "PBSZ =%lu", ibr.len);

    return (ibr.len);
}

/*
 * sec_putbuf
 *
 * Wrap the plaintext 'buf' data using gss_wrap and send
 * it out.
 *
 * returns:
 *    bytes written (success)
 *   -1 on error(errno set)
 *   -2 on security error
 */
static int
sec_putbuf(int fd, unsigned char *buf, int len)
{
    unsigned long net_len;
    int ret = 0;
    gss_buffer_desc in_buf, out_buf;
    OM_uint32 maj_stat, min_stat;
    int conf_state;

    in_buf.value = buf;
    in_buf.length = len;
    maj_stat = gss_wrap(&min_stat, gss_info.context,
		(gss_info.data_prot == PROT_P), GSS_C_QOP_DEFAULT,
		&in_buf, &conf_state, &out_buf);

    if (maj_stat != GSS_S_COMPLETE) {
	reply_gss_error(535, maj_stat, min_stat, gss_info.mechoid,
		gss_info.data_prot == PROT_P ? "GSSAPI wrap failed":
		"GSSAPI sign failed");
	return (-2);
    }

    net_len = (unsigned long)htonl((unsigned long) out_buf.length);

    if ((ret = looping_write(fd, (const char *)&net_len, 4)) != 4) {
	syslog(LOG_ERR, "Error writing net_len(%d): %m", net_len);
	ret = -1;
	goto putbuf_done;
    }

    if ((ret = looping_write(fd, out_buf.value, out_buf.length)) !=
	out_buf.length) {
	syslog(LOG_ERR, "Error writing %d bytes: %m", out_buf.length);
	ret = -1;
	goto putbuf_done;
    }
putbuf_done:

    gss_release_buffer(&min_stat, &out_buf);
    return (ret);
}

/*
 * sec_write
 *
 * If GSSAPI security is established, encode the output
 * and write it to the client.  Else, just write it directly.
 */
int
sec_write(int fd, char *buf, int len)
{
    int nbytes = 0;
    if (gss_info.data_prot == PROT_C ||
	!sec_check_mechanism(SEC_MECHANISM_GSS) ||
	!(gss_info.authstate & GSS_ADAT_DONE))
	nbytes = WRITE(fd, buf, len);
    else {
	/*
	 * Fill up the buffer before actually encrypting
	 * and writing it out.
	 */
	while ((obr.idx < obr.len) && (len > 0)) {
	    int n, ret;

	    /* how many bytes can we fit into the buffer? */
	    n = (len < (obr.len - obr.idx) ? len : obr.len - obr.idx);
	    memcpy(obr.buf + obr.idx, buf, n);

	    obr.idx += n;

	    if (obr.idx >= obr.len) {
		ret = sec_putbuf(fd, (unsigned char *)obr.buf, obr.idx);
		obr.idx = 0;
		if (ret < 0)
		    return (ret);
	    }
	    len -= n;
	    nbytes += n;
	}
    }

    return (nbytes);
}

/*
 * CCC
 *
 * Clear Command Channel.
 *
 * We will understand this command but not allow it in a secure
 * connection.  It is very dangerous to allow someone to degrade
 * the security of the command channel.  See RFC2228 for more info.
 */
void
ccc(void)
{
    /*
     * Once we have negotiated security successfully, do not allow the control
     * channel to be downgraded. It should be at least SAFE if not PRIVATE.
     */
    if (sec_check_mechanism(SEC_MECHANISM_GSS) &&
	(gss_info.authstate & GSS_ADAT_DONE) == GSS_ADAT_DONE)
	reply(534, "Control channel may not be downgraded");
    else {
	gss_info.ctrl_prot = PROT_C;
	set_control_security(SEC_CTRL_CLEARED);
	reply(200, "CCC ok");
    }
}

int
sec_putc(int c, FILE *stream)
{
    int ret = 0;

    /*
     * If we are NOT protecting the data OR GSSAPI data is not yet completed,
     * send plaintext.
     */
    if (gss_info.data_prot == PROT_C ||
	!sec_check_mechanism(SEC_MECHANISM_GSS) ||
	!(gss_info.authstate & GSS_ADAT_DONE))
	return (PUTC(c, stream));

    /*
     * Add the latest byte to the current buffer
     */
    if (obr.idx < obr.len) {
	obr.buf[obr.idx++] = (unsigned char)(c & 0xff);
    }

    if (obr.idx == obr.len) {
	ret = sec_putbuf(fileno(stream), (unsigned char *)obr.buf, obr.idx);
	if (ret >= 0)
	    ret = 0;
	obr.idx = 0;
    }

    return ((ret == 0 ? c : ret));
}

int
sec_fprintf(FILE *stream, char *fmt, ...)
{
    int ret;
    va_list ap;
    va_start(ap, fmt);

    if (gss_info.data_prot == PROT_C ||
	!sec_check_mechanism(SEC_MECHANISM_GSS) ||
	!(gss_info.authstate & GSS_ADAT_DONE)) {
	ret = VFPRINTF(stream, fmt, ap);
    } else {
	(void) vsnprintf(obr.buf, obr.len, fmt, ap);
	ret = sec_putbuf(fileno(stream), (unsigned char *)obr.buf,
		strlen(obr.buf));
    }
    va_end(ap);
    return (ret);
}

/*
 * sec_fflush
 *
 * If GSSAPI protection is configured, write out whatever remains in the output
 * buffer using the secure routines, otherwise just flush the stream.
 */
int
sec_fflush(FILE *stream)
{
    int ret = 0;

    if (gss_info.data_prot == PROT_C ||
	!sec_check_mechanism(SEC_MECHANISM_GSS) ||
	!(gss_info.authstate & GSS_ADAT_DONE)) {
	FFLUSH(stream);
	return (0);
    }
    if (obr.idx > 0) {
	ret = sec_putbuf(fileno(stream), (unsigned char *)obr.buf, obr.idx);
	obr.idx = 0;
    }

    if (ret >= 0)
	ret = sec_putbuf(fileno(stream), (unsigned char *)"", 0);
    /*
     * putbuf returns number of bytes or a negative value,
     * but fflush must return 0 or -1, so adjust the return
     * value so that a positive value is interpreted as success.
     */
    return (ret >= 0 ? 0 : ret);
}

/*
 * sec_getbytes
 *
 * Read and decrypt from the secure data channel.
 *
 * Return:
 *   > 0 == number of bytes available in gssbuf
 *   EOF == End of file.
 *   -2 == GSS error.
 *
 */
static int
sec_getbytes(int fd, char *buf, int nbytes)
{
    /*
     * Only read from the network if our current buffer is all used up.
     */
    if (ibr.idx >= ibr.clen) {
	int kerror;
	int conf_state;
	unsigned int length;
	gss_buffer_desc xmit_buf, msg_buf;
	OM_uint32 maj_stat, min_stat;

	if ((kerror = looping_read(fd, (char *)&length, 4)) != 4) {
	    reply(535, "Couldn't read PROT buffer length: %d/%s",
		kerror, (kerror == -1) ? strerror(errno) : "premature EOF");
	    return (-2);
	}

	if ((length = (unsigned int)ntohl(length)) > ibr.len) {
	    reply(535, "Length(%d) > PBSZ(%d)", length, ibr.len);
	    return (-2);
	}

	if (length > 0) {
	    if ((kerror = looping_read(fd, ibr.buf, length)) !=
		length) {
		reply(535, "Couldn't read %u byte PROT buf: %s",
		    length, (kerror == -1) ? strerror(errno) : "premature EOF");
		return (-2);
	    }

	    xmit_buf.value = (char *)ibr.buf;
	    xmit_buf.length = length;

	    conf_state = (gss_info.data_prot == PROT_P);

	    /* decrypt/verify the message */
	    maj_stat = gss_unwrap(&min_stat, gss_info.context,
		    &xmit_buf, &msg_buf, &conf_state, NULL);
	    if (maj_stat != GSS_S_COMPLETE) {
		reply_gss_error(535, maj_stat, min_stat,
		    gss_info.mechoid, (gss_info.data_prot == PROT_P)?
		    "failed unwrapping ENC message":
		    "failed unwrapping MIC message");
		return (-2);
	    }

	    memcpy(ibr.buf, msg_buf.value, msg_buf.length);
	    ibr.clen = msg_buf.length;
	    ibr.idx = 0;

	    gss_release_buffer(&min_stat, &msg_buf);
	} else {
	    ibr.idx = 0;
	    ibr.clen = 0;
	    return (EOF);
	}
    }

    /*
     * If there are 'nbytes' of plain text available, use them, else
     * get whats available.
     */
    nbytes = (nbytes < (ibr.clen - ibr.idx) ? nbytes : ibr.clen - ibr.idx);

    memcpy(buf, ibr.buf + ibr.idx, nbytes);
    ibr.idx += nbytes;

    return ((nbytes == 0 ? EOF : nbytes));
}

/*
 * Get a buffer of 'maxlen' bytes from the client. If we are using GSSAPI
 * protection, use the secure input buffer.
 */
int
sec_read(int fd, char *buf, int maxlen)
{
    int nbytes = 0;

    if (gss_info.data_prot != PROT_C &&
	sec_check_mechanism(SEC_MECHANISM_GSS) &&
	(gss_info.authstate & GSS_ADAT_DONE)) {
	/* Get as much data as possible */
	nbytes = sec_getbytes(fd, buf, maxlen);
	if (nbytes == EOF)
	    nbytes = 0;
    } else {
	nbytes = READ(fd, buf, maxlen);
    }
    return (nbytes);
}

/*
 * sec_getc
 *
 * Get a single character from the secure network buffer.
 */
int
sec_getc(FILE *stream)
{
    int nbytes;
    unsigned char c;

    if (gss_info.data_prot != PROT_C &&
	sec_check_mechanism(SEC_MECHANISM_GSS) &&
	(gss_info.authstate & GSS_ADAT_DONE)) {
	nbytes = sec_getbytes(fileno(stream), (char *)&c, 1);
	if (nbytes > 0)
	    nbytes = (int)c;
	return (nbytes);
    } else
	return (GETC(stream));
}

/*
 * sec_reply
 *
 * Securely encode a reply destined for the ftp client
 * depending on the GSSAPI settings.
 */
int
sec_reply(char *buf, int bufsiz, int n)
{
    char out[BUFSIZ], in[BUFSIZ];
    gss_buffer_desc in_buf, out_buf;
    OM_uint32 maj_stat, min_stat;
    int conf_state, length, kerror;
    int ret = 0;

    if (debug)
	syslog(LOG_DEBUG, "encoding %s", buf);

    in_buf.value = buf;
    in_buf.length = strlen(buf) + 1;
    maj_stat = gss_wrap(&min_stat, gss_info.context,
		    gss_info.ctrl_prot == PROT_P, GSS_C_QOP_DEFAULT,
		    &in_buf, &conf_state, &out_buf);
    if (maj_stat != GSS_S_COMPLETE) {
	syslog(LOG_ERR, "gss_wrap %s did not complete",
	    (gss_info.ctrl_prot == PROT_P) ? "ENC": "MIC");
	ret = -2;
    } else if ((gss_info.ctrl_prot == PROT_P) && !conf_state) {
	syslog(LOG_ERR, "gss_wrap did not encrypt message");
	ret = -2;
    } else {
	memcpy(out, out_buf.value, out_buf.length);
	length = out_buf.length;
	gss_release_buffer(&min_stat, &out_buf);
	ret = 0;
    }
    /*
     * Base64 encode the reply.  encrypted "out" becomes
     * encoded "in" buffer.  Stick it all back in 'buf' for
     * final output.
     */
    if ((kerror = radix_encode((unsigned char *)out,
	(unsigned char *)in, &length, 0))) {
	syslog(LOG_ERR, "Couldn't encode reply(%s)", radix_error(kerror));
	strlcpy(buf, in, bufsiz-1);
    } else {
	snprintf(buf, bufsiz, "%s%c%s",
	    gss_info.ctrl_prot == PROT_P ? "632" : "631", n ? ' ' : '-', in);
    }
    return (ret);
}

/*
 * sec_decode_command
 *
 * If a command is received which is encoded(ENC, MIC, or CONF),
 * decode it here using GSSAPI.
 */
char *
sec_decode_command(char *cmd)
{
    char out[2048], *cp;
    int len, mic;
    gss_buffer_desc xmit_buf, msg_buf;
    OM_uint32 maj_stat, min_stat;
    int conf_state;
    int kerror;
    char *cs;
    char *s = cmd;

    if ((cs = strpbrk(s, " \r\n")))
	*cs++ = '\0';
    upper(s);

    if ((mic = strcmp(s, "ENC")) != 0 && strcmp(s, "MIC") &&
	strcmp(s, "CONF")) {
	reply(533, "All commands must be protected.");
	syslog(LOG_ERR, "Unprotected command received %s", s);
	*s = '\0';
	return (s);
    }

    if ((cp = strpbrk(cs, " \r\n")))
	*cp = '\0';

    if ((kerror = radix_encode((unsigned char *)cs,
		    (unsigned char *)out, &len, 1))) {
	reply(501, "Can't base 64 decode argument to %s command(%s)",
	    mic ? "MIC" : "ENC", radix_error(kerror));
	*s = '\0';
	return (s);
    }

    if (debug)
	syslog(LOG_DEBUG, "getline got %d from %s <%s >\n",
	    len, cs, mic ? "MIC" : "ENC");

    xmit_buf.value = out;
    xmit_buf.length = len;

    /* decrypt the message */
    conf_state = !mic;
    maj_stat = gss_unwrap(&min_stat, gss_info.context, &xmit_buf,
		&msg_buf, &conf_state, NULL);
    if (maj_stat == GSS_S_CONTINUE_NEEDED) {
	if (debug) syslog(LOG_DEBUG, "%s-unwrap continued",
		mic ? "MIC" : "ENC");
	reply(535, "%s-unwrap continued, oops", mic ? "MIC" : "ENC");
	*s = 0;
	return (s);
    }
    if (maj_stat != GSS_S_COMPLETE) {
	reply_gss_error(535, maj_stat, min_stat, gss_info.mechoid,
		mic ? "failed unwrapping MIC message":
		"failed unwrapping ENC message");
	*s = 0;
	return (s);
    }

    memcpy(s, msg_buf.value, msg_buf.length);
    strcpy(s + msg_buf.length-(s[msg_buf.length-1] ? 0 : 1), "\r\n");
    gss_release_buffer(&min_stat, &msg_buf);

    return (s);
}

#endif /* defined(USE_GSS) */
