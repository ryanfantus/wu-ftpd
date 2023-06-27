/*
 * Copyright (c) 1999, 2000 Peter 'Luna' Runestig <peter@runestig.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modifi-
 * cation, are permitted provided that the following conditions are met:
 *
 *    o Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    o Redistributions in binary form must reproduce the above copyright no-
 *      tice, this list of conditions and the following disclaimer in the do-
 *      cumentation and/or other materials provided with the distribution.
 *
 *    o The names of the contributors may not be used to endorse or promote
 *      products derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LI-
 * ABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUEN-
 * TIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEV-
 * ER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABI-
 * LITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Portions Copyright (c) 2001 IBM (paulfordh@uk.ibm.com)
 * All rights reserved.
 *
 * Use and distribution of this software and its source code are governed
 * by the terms and conditions of the WU-FTPD Software License ("LICENSE").
 *
 * If you did not receive a copy of the license, it may be obtained online
 * at http://www.wu-ftpd.info/license.html.
 *
 * $Id: tlsutil.c,v 1.12 2016/03/14 23:57:37 wmaton Exp $
 */

#include "config.h"

#if defined(USE_TLS)

#  if !defined(lint)
static char copyright[] =
"@(#) Copyright (c) Peter 'Luna' Runestig 1999, 2000 <peter@runestig.com>";
#  endif /* !defined(lint) */ 

#  include <string.h>
#  include <errno.h>
#  include <syslog.h>
#  include <unistd.h>
#  include <pwd.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <sys/poll.h>
#  include <openssl/ssl.h>
#  include <openssl/x509v3.h>
#  include <openssl/err.h>
#  include <openssl/rand.h>
#  include "tls_dh.h"
#  include "tlsutil.h"
#  include <signal.h>
SIGNAL_TYPE lostconn(int sig);

#  if defined(TLS_STDC)
#    include <stdarg.h>
#  else /* !(defined(TLS_STDC)) */ 
#    include <varargs.h>
#  endif /* !(defined(TLS_STDC)) */ 

#  if OPENSSL_VERSION_NUMBER < 0x00905100
/* ASN1_BIT_STRING_cmp was renamed in 0.9.5 */
#    define M_ASN1_BIT_STRING_cmp ASN1_BIT_STRING_cmp
#  endif /* OPENSSL_VERSION_NUMBER < 0x00905100 */ 

#  define TLS_AUTH_SERVER	1
#  define TLS_AUTH_CLIENT_CAN	2
#  define TLS_AUTH_CLIENT_MUST	3

#  define TLS_CERTPASS_NOPASS	1
#  define TLS_CERTPASS_REQUIRE	2

#  define DEFRSACERTFILE	"ftpd-rsa.pem"
#  define DEFRSAKEYFILE		"ftpd-rsa-key.pem" 
#  define DEFDSACERTFILE	"ftpd-dsa.pem"
#  define DEFDSAKEYFILE		"ftpd-dsa-key.pem" 
#  define DEFCRLFILE		"ftpd-crl.pem"
#  define DEFDHPARAMFILE	"ftpd-dhparam.pem"
#  define DEFAULTCIPHERLIST	"ALL:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA"

#  define DEFDEBUGFILE		"ftpd.debug"
#  define DEFSYSTEMCERTDIR	"/usr/local/ftpsd/usercerts"
#  define DEFAULTAUTHMODE	TLS_AUTH_CLIENT_CAN
#  define DEFAULTCERTPASSMODE	TLS_CERTPASS_NOPASS

/* define if you want to check for OpenSSL-related memory leaks */
/*#define DEBUG_OPENSSL_MEM*/

typedef struct {
    SSL *ssl;
    int sock;
} CONN;

void	reply(int, const char *, ...);
void	dologout(int status);

char	*file_fullpath(char *fn);
int	x509_to_user(X509 *peer_cert, char *userid, int len);

int	tls_no_verify = 0;
#  if defined(TLS_DEBUG)
FILE *DEBUG_FILE = NULL;
#  endif /* defined(TLS_DEBUG) */ 
int     tls_allow_auth_ssl = 0;
int     tls_bad_auth_ssl_reply = 0;
int     tls_debugging = 0;
int     tls_allow_ccc = 0;
int     tls_dont_use_tls = 0;
int     tls_rsa_format = SSL_FILETYPE_PEM;
int     tls_log_all_data = 0;
/* defaults for the 3 below are in tls_set_defaults() */
int     tls_protect_user;
int     tls_force_data_prot_p;
int     tls_only_client_cert_auth;
int 	tls_authentication_mode = DEFAULTAUTHMODE;
int	tls_certpass_mode = DEFAULTCERTPASSMODE;
char 	*tls_config_file = NULL;

int  	tls_config_file_PARM = 0;
int  	tls_rsa_key_file_PARM = 0;
int  	tls_password_PARM = 0;
int 	tls_rsa_cert_file_PARM = 0;
int  	tls_dsa_key_file_PARM = 0;
int 	tls_dsa_cert_file_PARM = 0;
int 	tls_crl_file_PARM = 0;
int 	tls_crl_dir_PARM = 0;
int 	tls_CApath_PARM = 0;
int 	tls_CAfile_PARM = 0;
int 	tls_dhparam_file_PARM = 0;
int 	tls_rand_file_PARM = 0;
int 	tls_cipher_list_PARM = 0;
int 	tls_authentication_mode_PARM = 0;
int	tls_certpass_mode_PARM = 0;
void tls_start_debugging(void);
char	*tls_debug_filename = NULL;
char	*tls_system_certdir = NULL;
char	*tls_CApath = NULL;
char	*tls_CAfile = NULL;
int 	tls_debug_filename_PARM = 0;
int 	tls_system_certdir_PARM = 0;
int     verify_error_flag = 0;
SSL_CTX	*ssl_ctx = NULL;
X509_STORE *crl_store = NULL;
char 	*tls_rsa_key_file = NULL;
char 	*tls_password = NULL;
char	*tls_rsa_cert_file = NULL;
char 	*tls_dsa_key_file = NULL;
char	*tls_dsa_cert_file = NULL;
char	*tls_crl_file = NULL;
char	*tls_crl_dir = NULL;
char	*tls_dhparam_file = NULL;
char	*tls_rand_file = NULL;
char	*tls_cipher_list = NULL;
CONN	data_conn = { NULL, -1 }, ctrl_conn = { NULL, -1 };
DH      *tmp_dh = NULL;
RSA     *tmp_rsa = NULL;

/*
 * sending ASCII mode data one byte at a time is _incredibly_
 * expensive when using TLS (each char takes about 30 bytes
 * when wrapped in the TLS packet).  This define puts in code to
 * buffer up the PUTC commands into chunks
 */

#define BUFFER_TLS_PUTC

#if defined (BUFFER_TLS_PUTC)
/* 
 * the size of the PUTC buffer - feel free to tweak
 */  
#    define PUTC_BUFFERSIZE 1024
/* 
 * the space to keep the buffer
 *
 * NOTE: there is only one buffer for the simple reason that 
 *       a scour through the code ensured that only the data 
 *       connection used PUTC - as such, there is no need 
 *       to keep multiple buffers (we can only have one
 *       data connection at once).  If PUTC is used on the 
 *       control connection then you will need to hack stuff.
 */  
static int fputc_buflen = 0;
static unsigned char fputc_buffer[PUTC_BUFFERSIZE];
/*
 * function prototype
 */
void tls_fputc_flush(int fd);
#endif /* defined(BUFFER_TLS_PUTC) */



SSL *SOCK_TO_SSL(int s)
{
    /* stdin/stdout needs special treatment since it's two different file
     * numbers reffering to the same socket
     */
    if (s == 0 || s == 1) {
	if (data_conn.sock == 0 || data_conn.sock == 1)
            {
#  if defined(TLS_DEBUG)
            tls_debug("SOCK_TO_SSL - DATA - stdio\n");
#  endif /* defined(TLS_DEBUG) */ 
	    return data_conn.ssl;
            }
	else if (ctrl_conn.sock == 0 || ctrl_conn.sock == 1)
            {
#  if defined(TLS_DEBUG)
            tls_debug("SOCK_TO_SSL - CTRL - stdio\n");
#  endif /* defined(TLS_DEBUG) */ 
	    return ctrl_conn.ssl;
            }
	else
            {
#  if defined(TLS_DEBUG)
            tls_debug("SOCK_TO_SSL - PLAIN - stdio\n");
#  endif /* defined(TLS_DEBUG) */ 
	    return NULL;
            }
    } else
        {
#  if defined(TLS_DEBUG)
        if(s == data_conn.sock)
            tls_debug("SOCK_TO_SSL - DATA (ssl handle = %p)\n",data_conn.ssl);
        else if(s == ctrl_conn.sock)
            tls_debug("SOCK_TO_SSL - CTRL (ssl handle = %p)\n",ctrl_conn.ssl);
        else
            tls_debug("SOCK_TO_SSL - PLAIN\n");
#  endif /* defined(TLS_DEBUG) */ 
	return s == data_conn.sock ? data_conn.ssl :
	     ( s == ctrl_conn.sock ? ctrl_conn.ssl : NULL );
        }
}

/* we need this so we don't mix static and malloc'ed strings */
void tls_set_defaults(void)
{
    static char rand_file[200];
    if (!tls_rsa_key_file && (tls_rsa_key_file = malloc(strlen(DEFRSAKEYFILE) + 1)))
    	strcpy(tls_rsa_key_file, DEFRSAKEYFILE);
    if (!tls_rsa_cert_file && (tls_rsa_cert_file = malloc(strlen(DEFRSACERTFILE) + 1)))
    	strcpy(tls_rsa_cert_file, DEFRSACERTFILE);
    if (!tls_dsa_key_file && (tls_dsa_key_file = malloc(strlen(DEFDSAKEYFILE) + 1)))
    	strcpy(tls_dsa_key_file, DEFDSAKEYFILE);
    if (!tls_dsa_cert_file && (tls_dsa_cert_file = malloc(strlen(DEFDSACERTFILE) + 1)))
    	strcpy(tls_dsa_cert_file, DEFDSACERTFILE);
    if (!tls_crl_file && (tls_crl_file = malloc(strlen(DEFCRLFILE) + 1)))
    	strcpy(tls_crl_file, DEFCRLFILE);
    if (!tls_crl_dir && (tls_crl_dir = malloc(strlen(X509_get_default_cert_area()) + 5)))
    	sprintf(tls_crl_dir, "%s/crl", X509_get_default_cert_area());
    if (!tls_dhparam_file && (tls_dhparam_file = malloc(strlen(DEFDHPARAMFILE) + 1)))
    	strcpy(tls_dhparam_file, DEFDHPARAMFILE);
    if (!tls_cipher_list && (tls_cipher_list = malloc(strlen(DEFAULTCIPHERLIST) + 1)))
    	strcpy(tls_cipher_list, DEFAULTCIPHERLIST);


    /* the default ftpd's rand file is (openssl-dir)/.rnd */
    snprintf(rand_file, sizeof(rand_file), "%s/.rnd", X509_get_default_cert_area());
    if ((tls_rand_file = malloc(strlen(rand_file) + 1)))
         strcpy(tls_rand_file, rand_file);

    if (!tls_debug_filename && (tls_debug_filename = malloc(strlen(DEFDEBUGFILE) + 1)))
    	strcpy(tls_debug_filename, DEFDEBUGFILE);
    if (!tls_system_certdir && (tls_system_certdir = malloc(strlen(DEFSYSTEMCERTDIR) + 1)))
    	strcpy(tls_system_certdir, DEFSYSTEMCERTDIR);

   /* no default for tls_config_file */
   /* no default for tls_password */
   /* no default for tls_CApath */
   /* no default for tls_CAfile */

#  if defined(FORCE_TLS)
#    if !defined(USE_TLS)
#      error FORCE_TLS is defined but USE_TLS is not !
#    endif /* !defined(USE_TLS) */ 
tls_protect_user = 1;
tls_force_data_prot_p = 1;
tls_only_client_cert_auth = 1;
#  else /* !(defined(FORCE_TLS)) */ 
tls_protect_user = 0;
tls_force_data_prot_p = 0;
tls_only_client_cert_auth = 0;
#  endif /* !(defined(FORCE_TLS)) */ 

	

}

void tls_update_parm(char **tag,
                     char *value,
                     int parmOrFile, 
                     int *parmFlag)
   {
   if((TLS_OPTARG_PARM == parmOrFile) || (0 == (*parmFlag)))
      {
      if (*tag)
         free(*tag);
      if ((*tag = malloc(strlen(value) + 1)))
         strcpy(*tag, value);
      if(TLS_OPTARG_PARM == parmOrFile)
         {
         *parmFlag = 1;
         }
      }
   else
      {
      tls_debug("ConfigFile - overidden by command line\n");
      }
   return;
   }


void tls_optarg(char *optarg,int parmOrFile)
{
    char *p;

    if ((p = strchr(optarg, '='))) {
    	*p++ = 0;
	if (!strcmp(optarg, "cert") || !strcmp(optarg, "rsacert")) {
            tls_update_parm(&tls_rsa_cert_file,p,
                            parmOrFile,&tls_rsa_cert_file_PARM);
	}
	else if (!strcmp(optarg, "key") || !strcmp(optarg, "rsakey")) {
            tls_update_parm(&tls_rsa_key_file,p,
                            parmOrFile,&tls_rsa_key_file_PARM);
	}
        else if (!strcmp(optarg, "CApath")) {
            tls_update_parm(&tls_CApath,p,
                            parmOrFile,&tls_CApath_PARM);
        }
        else if (!strcmp(optarg, "CAfile")) {
            tls_update_parm(&tls_CAfile,p,
                            parmOrFile,&tls_CAfile_PARM);
        }
        else if (!strcmp(optarg, "password")) {
            tls_update_parm(&tls_password,p,
                            parmOrFile,&tls_password_PARM);
        }
	else if (!strcmp(optarg, "dsacert")) {
            tls_update_parm(&tls_dsa_cert_file,p,
                            parmOrFile,&tls_dsa_cert_file_PARM);
	}
	else if (!strcmp(optarg, "dsakey")) {
            tls_update_parm(&tls_dsa_key_file,p,
                            parmOrFile,&tls_dsa_key_file_PARM);
	}
	else if (!strcmp(optarg, "dhparam")) {
            tls_update_parm(&tls_dhparam_file,p,
                            parmOrFile,&tls_dhparam_file_PARM);
	}
	else if (!strcmp(optarg, "crlfile")) {
            tls_update_parm(&tls_crl_file,p,
                            parmOrFile,&tls_crl_file_PARM);
	}
	else if (!strcmp(optarg, "crldir")) {
            tls_update_parm(&tls_crl_dir,p,
                            parmOrFile,&tls_crl_dir_PARM);
	}
	else if (!strcmp(optarg, "cipher")) {
            tls_update_parm(&tls_cipher_list,p,
                            parmOrFile,&tls_cipher_list_PARM);
	}
	else if (!strcmp(optarg, "randfile")) {
            tls_update_parm(&tls_rand_file,p,
                            parmOrFile,&tls_rand_file_PARM);
	}
	else if (!strcmp(optarg, "debugfile")) {
            tls_update_parm(&tls_debug_filename,p,
                            parmOrFile,&tls_debug_filename_PARM);
	}
	else if (!strcmp(optarg, "systemcertdir")) {
            tls_update_parm(&tls_system_certdir,p,
                            parmOrFile,&tls_system_certdir_PARM);
	}
	else if (!strcmp(optarg, "authmode")) {
            if((TLS_OPTARG_PARM == parmOrFile) ||
               (0 == tls_authentication_mode_PARM))  {
               tls_authentication_mode_PARM = 1;
               if(0 == strncmp(p,"server",6)) {
                  tls_authentication_mode = TLS_AUTH_SERVER;
               }
               if(0 == strncmp(p,"client_can",9)) {
                  tls_authentication_mode = TLS_AUTH_CLIENT_CAN;
               }
               if(0 == strncmp(p,"client_must",10)) {
                  tls_authentication_mode = TLS_AUTH_CLIENT_MUST;
               }
            }
	}
        else if (!strcmp(optarg, "certpass")) {
            if((TLS_OPTARG_PARM == parmOrFile) ||
               (0 == tls_certpass_mode_PARM))  {
               tls_certpass_mode_PARM = 1;
               if(0 == strncmp(p,"certok",6)) {
                  tls_certpass_mode = TLS_CERTPASS_NOPASS;
               }
               if(0 == strncmp(p,"needpass",8)) {
                  tls_certpass_mode = TLS_CERTPASS_REQUIRE;
               }
            }
        }
	else if (!strcmp(optarg, "config")) {
            if(TLS_OPTARG_PARM == parmOrFile) {
               tls_update_parm(&tls_config_file,p,
                               parmOrFile,&tls_config_file_PARM);
	    }
	}
        else {
           if(TLS_OPTARG_PARM == parmOrFile)
              {
              syslog(LOG_INFO,"wu-ftpd - ignored parm on command line [%s]",optarg);
              }
           else
              {
              syslog(LOG_INFO,"wu-ftpd - ignored parm in config file [%s]",optarg);
              }
	}
    } else {
        if (!strcmp(optarg, "certsok"))
            tls_no_verify  = 1;
        else if (!strcmp(optarg, "debug"))
            {
            if(0 == tls_debugging)
               {
               tls_debugging = 1;
               tls_start_debugging();
               }
            }
        else if (!strcmp(optarg, "allow_auth_ssl")) /* BAD OPTION */
            tls_allow_auth_ssl = 1;
        else if (!strcmp(optarg, "bad_auth_ssl_reply")) /* BAD OPTION */
            tls_bad_auth_ssl_reply = 1;
        else if (!strcmp(optarg, "tlsonly"))
            tls_protect_user = 1;
        else if (!strcmp(optarg, "protect_user"))
            tls_protect_user = 1;
#if !defined(FORCE_TLS)
	/*
	 * we won't allow the CCC command if the binary is going to enforce 
	 *  security
	 */
        else if (!strcmp(optarg, "allowccc"))
            tls_allow_ccc = 1;
        else if (!strcmp(optarg, "notls"))
            tls_dont_use_tls = 1;
#endif /* ! FORCE_TLS */
        else if (!strcmp(optarg, "logalldata"))
            tls_log_all_data = 1;
        else if (!strcmp(optarg, "rsader"))
            tls_rsa_format = SSL_FILETYPE_ASN1;
        else if (!strcmp(optarg, "tlsdata")) 
            tls_force_data_prot_p = 1;
        else if (!strcmp(optarg, "clientcert"))
            tls_only_client_cert_auth = 1;
        else {
           if(TLS_OPTARG_PARM == parmOrFile)
              {
              syslog(LOG_INFO,"wu-ftpd - ignored flag on command line [%s]",optarg);
              }
           else
              {
              syslog(LOG_INFO,"wu-ftpd - ignored flag in config file [%s]",optarg);
              }
	}
    }
}

int tls_active(int s)
{
#  if defined(TLS_DEBUG)
            tls_debug("tls_active [%d] ",s);
#  endif /* defined(TLS_DEBUG) */ 
    if (SOCK_TO_SSL(s))
	return 1;
    else
	return 0;
}

/* if we are using OpenSSL 0.9.6 or newer, we want to use X509_NAME_print_ex()
 * instead of X509_NAME_oneline().
 */
char *x509_name_oneline(X509_NAME *n, char *buf, int len)
{
#  if OPENSSL_VERSION_NUMBER < 0x000906000
    return X509_NAME_oneline(n, buf, len);
#  else /* !(OPENSSL_VERSION_NUMBER < 0x000906000) */ 
    BIO *mem = BIO_new(BIO_s_mem());
    char *data = NULL;
    int data_len = 0, ok;
    
    ok = X509_NAME_print_ex(mem, n, 0, XN_FLAG_ONELINE);
    if (ok)
	data_len = BIO_get_mem_data(mem, &data);
    if (data) {
	/* the 'data' returned is not '\0' terminated */
	if (buf) {
	    memcpy(buf, data, data_len < len ? data_len : len);
	    buf[data_len < len ? data_len : len - 1] = 0;
	    BIO_free(mem);
	    return buf;
	} else {
	    char *b = malloc(data_len + 1);
	    if (b) {
		memcpy(b, data, data_len);
		b[data_len] = 0;
	    }
	    BIO_free(mem);
	    return b;
	}
    } else {
	BIO_free(mem);
	return NULL;
    }
#  endif /* !(OPENSSL_VERSION_NUMBER < 0x000906000) */ 
}

char *tls_get_subject_name(SSL *ssl)
{
    static char name[256];
    X509 *cert;

    if ((cert = SSL_get_peer_certificate(ssl))) {
	x509_name_oneline(X509_get_subject_name(cert), name, sizeof(name));
	X509_free(cert);
	return name;
    }
    else
	return NULL;
}

DH *tmp_dh_cb(SSL *ssl, int is_export, int keylength)
{
    FILE *fp;

    if (!tmp_dh) {
        /* first try any 'tls_dhparam_file', else use built-in dh params */
        if (tls_dhparam_file && (fp = fopen(tls_dhparam_file, "r"))) {
            tmp_dh = PEM_read_DHparams(fp, NULL, NULL, NULL);
            fclose(fp);
            if (tmp_dh)
                return tmp_dh;
        }
        switch (keylength) {
            case 512:   return tmp_dh = get_dh512();
            case 768:   return tmp_dh = get_dh768();
            case 1024:  return tmp_dh = get_dh1024();
            case 1536:  return tmp_dh = get_dh1536();
            case 2048:  return tmp_dh = get_dh2048();
            default:    return tmp_dh = get_dh1024();
        }
    }
    else
    	return tmp_dh;
}

RSA *tmp_rsa_cb(SSL *ssl, int is_export, int keylength)
{
    if (!tmp_rsa)
        tmp_rsa = RSA_generate_key(keylength, RSA_F4, NULL, NULL);
    return tmp_rsa;
}

/* check_file() expands 'file' to an existing full path or NULL if not found */
void check_file(char **file)
{
    char *p;
    
    if (*file) {
    	p = file_fullpath(*file);
	if (p == *file)	/* same pointer returned from file_fullpath() */
	    return;
	free(*file);
	if (p) {
	    *file = malloc(strlen(p) + 1);
	    strcpy(*file, p);
	}
	else
	    *file = NULL;
    }
}

/* this one is (very much!) based on work by Ralf S. Engelschall <rse@engelschall.com>.
 * comments by Ralf.
 */
int verify_crl(int ok, X509_STORE_CTX *ctx)
{
    X509_OBJECT obj;
    X509_NAME *subject;
    X509_NAME *issuer;
    X509 *xs;
    X509_CRL *crl;
    X509_REVOKED *revoked;
    X509_STORE_CTX store_ctx;
    long serial;
    int i, n, rc;
    char *cp;
#  if defined(TLS_DEBUG)
   tls_debug("tls_verify_crl\n");
#  endif /* defined(TLS_DEBUG) */ 

    /*
     * Unless a revocation store for CRLs was created we
     * cannot do any CRL-based verification, of course.
     */
    if (!crl_store)
        return ok;

    /*
     * Determine certificate ingredients in advance
     */
    xs      = X509_STORE_CTX_get_current_cert(ctx);
    subject = X509_get_subject_name(xs);
    issuer  = X509_get_issuer_name(xs);

    /*
     * OpenSSL provides the general mechanism to deal with CRLs but does not
     * use them automatically when verifying certificates, so we do it
     * explicitly here. We will check the CRL for the currently checked
     * certificate, if there is such a CRL in the store.
     *
     * We come through this procedure for each certificate in the certificate
     * chain, starting with the root-CA's certificate. At each step we've to
     * both verify the signature on the CRL (to make sure it's a valid CRL)
     * and it's revocation list (to make sure the current certificate isn't
     * revoked).  But because to check the signature on the CRL we need the
     * public key of the issuing CA certificate (which was already processed
     * one round before), we've a little problem. But we can both solve it and
     * at the same time optimize the processing by using the following
     * verification scheme (idea and code snippets borrowed from the GLOBUS
     * project):
     *
     * 1. We'll check the signature of a CRL in each step when we find a CRL
     *    through the _subject_ name of the current certificate. This CRL
     *    itself will be needed the first time in the next round, of course.
     *    But we do the signature processing one round before this where the
     *    public key of the CA is available.
     *
     * 2. We'll check the revocation list of a CRL in each step when
     *    we find a CRL through the _issuer_ name of the current certificate.
     *    This CRLs signature was then already verified one round before.
     *
     * This verification scheme allows a CA to revoke its own certificate as
     * well, of course.
     */

    /*
     * Try to retrieve a CRL corresponding to the _subject_ of
     * the current certificate in order to verify it's integrity.
     */
    memset((char *)&obj, 0, sizeof(obj));
    X509_STORE_CTX_init(&store_ctx, crl_store, NULL, NULL);
    rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, subject, &obj);
    X509_STORE_CTX_cleanup(&store_ctx);
    crl = obj.data.crl;
    if (rc > 0 && crl != NULL) {
        /*
         * Verify the signature on this CRL
         */
        if (X509_CRL_verify(crl, X509_get_pubkey(xs)) <= 0) {
            syslog(LOG_ERR, "Invalid signature on CRL!");
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
            X509_OBJECT_free_contents(&obj);
            return 0;
        }

        /*
         * Check date of CRL to make sure it's not expired
         */
        i = X509_cmp_current_time(X509_CRL_get_nextUpdate(crl));
        if (i == 0) {
            syslog(LOG_ERR, "Found CRL has invalid nextUpdate field.");
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
            X509_OBJECT_free_contents(&obj);
            return 0;
        }
        if (i < 0) {
            syslog(LOG_ERR,
		"Found CRL is expired - revoking all certificates until you get updated CRL.");
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_HAS_EXPIRED);
            X509_OBJECT_free_contents(&obj);
            return 0;
        }
        X509_OBJECT_free_contents(&obj);
    }

    /*
     * Try to retrieve a CRL corresponding to the _issuer_ of
     * the current certificate in order to check for revocation.
     */
    memset((char *)&obj, 0, sizeof(obj));
    X509_STORE_CTX_init(&store_ctx, crl_store, NULL, NULL);
    rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, issuer, &obj);
    X509_STORE_CTX_cleanup(&store_ctx);
    crl = obj.data.crl;
    if (rc > 0 && crl != NULL) {
        /*
         * Check if the current certificate is revoked by this CRL
         */
        n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
        for (i = 0; i < n; i++) {
            revoked = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
            if (ASN1_INTEGER_cmp(revoked->serialNumber, X509_get_serialNumber(xs)) == 0) {

                serial = ASN1_INTEGER_get(revoked->serialNumber);
                cp = x509_name_oneline(issuer, NULL, 0);
                syslog(LOG_ERR,
		    "Certificate with serial %ld (0x%lX) revoked per CRL from issuer %s",
                        serial, serial, cp ? cp : "(ERROR)");
                if (cp) free(cp);

                X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
                X509_OBJECT_free_contents(&obj);
                return 0;
            }
        }
        X509_OBJECT_free_contents(&obj);
    }
    return ok;
}

int verify_callback(int ok, X509_STORE_CTX *ctx)
{
#  if defined(TLS_DEBUG)
   tls_debug("tls_verify_callback\n");
#  endif /* defined(TLS_DEBUG) */ 
/* TODO: Make up my mind on what to accept or not.*/
    /* we can configure the server to skip the peer's cert verification */
    if (tls_no_verify)
    	return 1;
    ok = verify_crl(ok, ctx);
    if (!ok) {
    	switch (ctx->error) {
	    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
	    	syslog(LOG_ERR, "Error: Client's certificate is self signed.");
		ok = 0;
		break;
	    case X509_V_ERR_CERT_HAS_EXPIRED:
	    	syslog(LOG_ERR, "Error: Client's certificate has expired.");
		ok = 0;
		break;
	    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
	    	syslog(LOG_ERR,
		    "Error: Client's certificate issuer's certificate isn't available locally.");
		ok = 0;
		break;
	    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
	    	syslog(LOG_ERR, "Error: Unable to verify leaf signature.");
		ok = 0;
		break;
	    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		/* XXX this is strange. we get this error for certain clients (ie Jeff's
		 * kftp) when all is ok. I think it's because the client is actually
		 * sending the whole CA cert. this must be figured out, but we let it
		 * pass for now. if the CA cert isn't available locally, we will fail anyway.
		 */
	    	syslog(LOG_NOTICE, "Warning: Self signed certificate in chain.");
		ok = 1;
		break;
	    case X509_V_ERR_CERT_REVOKED:
	    	syslog(LOG_ERR, "Error: Certificate revoked.");
		ok = 0;
		break;
	    default:
	    	syslog(LOG_ERR,
		    "Error %d while verifying the client's certificate.", ctx->error);
		ok = 0;
	    	break;
	}
    }
    return ok;
}

int seed_PRNG(void)
{
    char stackdata[1024];
    FILE *fh;
    
#  if OPENSSL_VERSION_NUMBER >= 0x00905100
    if (RAND_status())
	return 0;     /* PRNG already good seeded */
#  endif /* OPENSSL_VERSION_NUMBER >= 0x00905100 */ 
    /* if the device '/dev/urandom' is present, OpenSSL uses it by default.
     * check if it's present, else we have to make random data ourselfs.
     */
    if ((fh = fopen("/dev/urandom", "r"))) {
	fclose(fh);
	return 0;
    }
    if (!RAND_load_file(tls_rand_file, 1024)) {
	/* no .rnd file found, create new seed */
	unsigned int c;
	c = time(NULL);
	RAND_seed(&c, sizeof(c));
	c = getpid();
	RAND_seed(&c, sizeof(c));
	RAND_seed(stackdata, sizeof(stackdata));
    }
#  if OPENSSL_VERSION_NUMBER >= 0x00905100
    if (!RAND_status())
	return 2;   /* PRNG still badly seeded */
#  endif /* OPENSSL_VERSION_NUMBER >= 0x00905100 */ 
    return 0;
}

/*
 * callback routine to provide password to OpenSSL PEM decode
 * routines
 */
int pem_password_callback(char *buf, int size, int rwflag, void *password)
{
   strlcpy(buf,(char *) password,size);
   return(strlen(buf));
}

int tls_init(void)
{
    int err;
#  if defined(DEBUG_OPENSSL_MEM)
    CRYPTO_malloc_debug_init();
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#  endif /* defined(DEBUG_OPENSSL_MEM) */ 
   int verify_mode;

    if(tls_dont_use_tls)
       {
       return 0;
       }

#  if defined(TLS_DEBUG)
   tls_debug("tls_init\n");
#  endif /* defined(TLS_DEBUG) */ 

    SSL_library_init();
    SSL_load_error_strings();
#  if OPENSSL_VERSION_NUMBER < 0x00905100
    SSLeay_add_all_algorithms();
#  else /* !(OPENSSL_VERSION_NUMBER < 0x00905100) */ 
    OpenSSL_add_all_algorithms();
#  endif /* !(OPENSSL_VERSION_NUMBER < 0x00905100) */ 
    ssl_ctx = SSL_CTX_new(SSLv23_method());
    if (!ssl_ctx) {
	syslog(LOG_ERR, "SSL_CTX_new() %s",
		(char *)ERR_error_string(ERR_get_error(), NULL));
	return 1;
    }
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
    switch(tls_certpass_mode)
       {
       case TLS_CERTPASS_NOPASS:
#  if defined(TLS_DEBUG)
          tls_debug("tls - secure PASS commands will be rejected\n");
#  endif /* defined(TLS_DEBUG) */ 
          break;
       case TLS_CERTPASS_REQUIRE:
#  if defined(TLS_DEBUG)
          tls_debug("tls - PASS required in addition to X.509 certs\n");
#  endif /* defined(TLS_DEBUG) */ 
          break;
       default:
          syslog(LOG_ERR,"ftpsd coding error - bad certpass mode\n");
          return 1;
       }
    switch(tls_authentication_mode)
       {
       case TLS_AUTH_SERVER:
          verify_mode=SSL_VERIFY_NONE;
#  if defined(TLS_DEBUG)
          tls_debug("tls - Server auth only\n");
#  endif /* defined(TLS_DEBUG) */ 
          break;
       case TLS_AUTH_CLIENT_CAN:
          verify_mode=SSL_VERIFY_PEER;
#  if defined(TLS_DEBUG)
          tls_debug("tls - Client auth allowed\n");
#  endif /* defined(TLS_DEBUG) */ 
          break;
       case TLS_AUTH_CLIENT_MUST:
          verify_mode=SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT; 
#  if defined(TLS_DEBUG)
          tls_debug("tls - Client auth mandatory\n");
#  endif /* defined(TLS_DEBUG) */ 
          break;
       default:
          syslog(LOG_ERR,"ftpsd coding error - bad auth mode\n");
          return 1;
       }
    SSL_CTX_set_verify(ssl_ctx, verify_mode, verify_callback);
    check_file(&tls_CAfile);
    if(tls_CAfile) {
         if(NULL == tls_CApath) {
    	    syslog(LOG_NOTICE, "CApath NULL with CAfile supplied");
         }
         (void) SSL_CTX_load_verify_locations(ssl_ctx,tls_CAfile,tls_CApath);
         (void) SSL_CTX_set_client_CA_list(ssl_ctx,SSL_load_client_CA_file(tls_CAfile));
    } else {
       if((TLS_AUTH_CLIENT_CAN == tls_authentication_mode) || 
          (TLS_AUTH_CLIENT_MUST == tls_authentication_mode)) {
    	  syslog(LOG_NOTICE, "CAfile missing with Client Auth allowed");
       } 
    } 
    SSL_CTX_set_default_verify_paths(ssl_ctx);

    /*
     * if we have a password then set it as default
     *  (John Nelson)
     */
    if(tls_password)
        {
        SSL_CTX_set_default_passwd_cb(ssl_ctx,pem_password_callback);
        SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx,tls_password);
        }

    /* set up session caching  */
    SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_session_id_context(ssl_ctx, (const unsigned char *) "1", 1);

    /* let's find out which files are available */
    check_file(&tls_rsa_cert_file);
    check_file(&tls_rsa_key_file);
    check_file(&tls_dsa_cert_file);
    check_file(&tls_dsa_key_file);
    check_file(&tls_crl_file);
    check_file(&tls_dhparam_file);
    check_file(&tls_CAfile);
    if (!tls_rsa_cert_file && !tls_dsa_cert_file) {
    	syslog(LOG_ERR, "No certificate files found!");
	return 2;
    }
    if (!tls_rsa_key_file)
       {
       if(SSL_FILETYPE_PEM == tls_rsa_format)
	  {
	  tls_rsa_key_file = tls_rsa_cert_file;
	  }
       else
	  {
	   syslog(LOG_ERR, "No RSA key file found!");
	   return 2;
	  }
       }
    if (!tls_dsa_key_file)
    	tls_dsa_key_file = tls_dsa_cert_file;
    
    if (tls_rsa_cert_file) {
        if(SSL_FILETYPE_PEM == tls_rsa_format)
	   {
	   err = SSL_CTX_use_certificate_file(ssl_ctx, 
					      tls_rsa_cert_file, 
					      tls_rsa_format);
	   if (err <= 0) {
	       syslog(LOG_ERR, "SSL_CTX_use_certificate_file(%s) %s", tls_rsa_cert_file,
		   (char *)ERR_error_string(ERR_get_error(), NULL));
	       return 3;
	   }
	   SSL_CTX_set_tmp_rsa_callback(ssl_ctx, tmp_rsa_cb);
        } else {
	   FILE *derHandle;

	   errno = 0;

	   derHandle = fopen(tls_rsa_cert_file,"r");
	   if(NULL != derHandle)
	      {
	      int derlen = 0;

	      (void) fseek(derHandle,0,SEEK_END);
	      derlen = ftell(derHandle);
	      (void) fseek(derHandle,0,SEEK_SET);
	      if(derlen > 0)
		 {
		 unsigned char *derdata;
		 derdata = malloc(derlen);
		 if(derdata != NULL)
		    {
		    size_t got;
		    memset(derdata,'\0',derlen);
		    got = fread(derdata,1,derlen,derHandle);
		    if(got == (size_t) derlen)
		       {
		       err = SSL_CTX_use_certificate_ASN1(ssl_ctx, 
							  derlen,
							  derdata);
		       if (err <= 0) 
			  {
			   syslog(LOG_ERR, 
				  "SSL_CTX_use_certificate_ASN1(%s)[%d] %s", 
				  tls_rsa_cert_file,
				  derlen,
				  (char *)ERR_error_string(ERR_get_error(), NULL));
			   return 3;
			  }
		       SSL_CTX_set_tmp_rsa_callback(ssl_ctx, tmp_rsa_cb);
		       /* it all worked */
		       }
		    else
		       {
		       /* read didn't get what we asked for */
		       syslog(LOG_ERR, 
			      "Read error trying to read certfile (%s) errno=%d",
			      tls_rsa_cert_file,
			      errno);
		       return 3;
		       }
		    free(derdata);
		    }
		 else
		    {
		    /* malloc failed */
		    syslog(LOG_ERR, 
			   "Malloc error trying to read certfile (%s) errno=%d",
			   tls_rsa_cert_file,
			   errno);
		    return 3;
		    }
		 }
	      else
		 {
		 /* file zero length */
		 syslog(LOG_ERR, 
			"Could not read empty certfile (%s) errno=%d",
			tls_rsa_cert_file,
			errno);
		 return 3;
		 }
	      fclose(derHandle);
	      }
	   else
	      {
	      /* file not opened */
	      syslog(LOG_ERR, 
		     "Could not open certfile (%s) errno=%d",
		     tls_rsa_cert_file,
		     errno);
	      return 3;
	      }
	}
    }
    if (tls_rsa_key_file) {
        if(SSL_FILETYPE_PEM == tls_rsa_format)
	   {
	   err = SSL_CTX_use_PrivateKey_file(ssl_ctx, 
					     tls_rsa_key_file, 
					     tls_rsa_format);
	   if (err <= 0) {
	       syslog(LOG_ERR, "SSL_CTX_use_PrivateKey_file(%s) %s", tls_rsa_key_file,
		   (char *)ERR_error_string(ERR_get_error(), NULL));
	       return 4;
	   }
	} else {
	   FILE *derHandle;

	   errno = 0;

	   derHandle = fopen(tls_rsa_key_file,"r");
	   if(NULL != derHandle)
	      {
	      int derlen = 0;

	      (void) fseek(derHandle,0,SEEK_END);
	      derlen = ftell(derHandle);
	      (void) fseek(derHandle,0,SEEK_SET);
	      if(derlen > 0)
		 {
		 unsigned char *derdata;
		 derdata = malloc(derlen);
		 if(derdata != NULL)
		    {
		    size_t got;
		    memset(derdata,'\0',derlen);
		    got = fread(derdata,1,derlen,derHandle);
		    if(got == (size_t) derlen)
		       {
		       err = SSL_CTX_use_RSAPrivateKey_ASN1(ssl_ctx, 
							    derdata,
							    derlen);
		       if (err <= 0) 
			  {
			   syslog(LOG_ERR, 
				  "SSL_CTX_use_RSAPrivateKey_ASN1(%s)[%d] %s", 
				  tls_rsa_key_file,
				  derlen,
				  (char *)ERR_error_string(ERR_get_error(), NULL));
			   return 4;
			  }
		       SSL_CTX_set_tmp_rsa_callback(ssl_ctx, tmp_rsa_cb);
		       /* it all worked */
		       }
		    else
		       {
		       /* read didn't get what we asked for */
		       syslog(LOG_ERR, 
			      "Read error trying to read keyfile (%s) errno=%d",
			      tls_rsa_key_file,
			      errno);
		       return 4;
		       }
		    free(derdata);
		    }
		 else
		    {
		    /* malloc failed */
		    syslog(LOG_ERR, 
			   "Malloc error trying to read keyfile (%s) errno=%d",
			   tls_rsa_key_file,
			   errno);
		    return 4;
		    }
		 }
	      else
		 {
		 /* file zero length */
		 syslog(LOG_ERR, 
			"Could not read empty keyfile (%s) errno=%d",
			tls_rsa_key_file,
			errno);
		 return 4;
		 }
	      fclose(derHandle);
	      }
	   else
	      {
	      /* file not opened */
	      syslog(LOG_ERR, 
		     "Could not open keyfile (%s) errno=%d",
		     tls_rsa_key_file,
		     errno);
	      return 4;
	      }
	}
    }
    if (tls_dsa_cert_file) {
	err = SSL_CTX_use_certificate_file(ssl_ctx, tls_dsa_cert_file, SSL_FILETYPE_PEM);
	if (err <= 0) {
	    syslog(LOG_ERR, "SSL_CTX_use_certificate_file(%s) %s", tls_dsa_cert_file,
		(char *)ERR_error_string(ERR_get_error(), NULL));
	    return 5;
	}
    }
    if (tls_dsa_key_file) {
	err = SSL_CTX_use_PrivateKey_file(ssl_ctx, tls_dsa_key_file, SSL_FILETYPE_PEM);
	if (err <= 0) {
	    syslog(LOG_ERR, "SSL_CTX_use_PrivateKey_file(%s) %s", tls_dsa_key_file,
	    	(char *)ERR_error_string(ERR_get_error(), NULL));
	    return 6;
	}
    }
    SSL_CTX_set_tmp_dh_callback(ssl_ctx, tmp_dh_cb);

    /* set up the CRL */
    if ((tls_crl_file || tls_crl_dir) && (crl_store = X509_STORE_new()))
	X509_STORE_load_locations(crl_store, tls_crl_file, tls_crl_dir);

    if (tls_cipher_list)
	SSL_CTX_set_cipher_list(ssl_ctx, tls_cipher_list);
    else
	syslog(LOG_NOTICE, "NULL tls_cipher_list!");
    if (seed_PRNG())
	syslog(LOG_NOTICE, "Wasn't able to properly seed the PRNG!");
    return 0;
}

char *tls_userid_from_client_cert(void)
{
    static char cn[256];
    static char *r = cn;
    static int again = 0;
    int err;
    X509 *client_cert;
#  if defined(TLS_DEBUG)
   tls_debug("tls_userid_from_client_cert\n");
#  endif /* defined(TLS_DEBUG) */ 

    if (!ctrl_conn.ssl)
    	return NULL;
    if (again)
    	return r;
    again = 1;
    if ((client_cert = SSL_get_peer_certificate(ctrl_conn.ssl))) {
    	/* call the custom function */
	err = x509_to_user(client_cert, cn, sizeof(cn));
	X509_free(client_cert);
	if (err)
	    return r = NULL;
	else
	    return r;
    }
    else
	return r = NULL;
}

int tls_is_user_valid(char *user)
/* check if clients cert is known to us */
{
    char buf[512];
    int r = 0;
    FILE *fp;
    X509 *client_cert, *file_cert;
    struct passwd *pwd;
#  if defined(TLS_DEBUG)
   tls_debug("tls_is_user_valid\n");
#  endif /* defined(TLS_DEBUG) */ 

    if (!ctrl_conn.ssl || !user)
	return 0;
    if (!(pwd = getpwnam(user)))
    	return 0;

    snprintf(buf, sizeof(buf), "%s/%s", tls_system_certdir,pwd->pw_name);
    if (!(fp = fopen(buf, "r"))) {
       snprintf(buf, sizeof(buf), "%s/.tlslogin", pwd->pw_dir);
       if (!(fp = fopen(buf, "r")))
    	 return 0;
    }

    if (!(client_cert = SSL_get_peer_certificate(ctrl_conn.ssl))) {
    	fclose(fp);
	return 0;
    }
    while ((file_cert = PEM_read_X509(fp, NULL, NULL, NULL))) {
	if (!M_ASN1_BIT_STRING_cmp(client_cert->signature, file_cert->signature))
	    r = 1;
	X509_free(file_cert);
	if (r)
	    break;
    }
    X509_free(client_cert);
    fclose(fp);
    return r;
}

void tls_close_session(CONN *conn)
{
   int rc;
   int shutcount = 0;
#  if defined(TLS_DEBUG)
   tls_debug("tls_close_session [%d]\n",conn->sock);
#  endif /* defined(TLS_DEBUG) */ 
   if (!conn->ssl)
      return;

   rc = SSL_shutdown(conn->ssl);
   /*
    * the rc of 0 from SSL_shutdown means - "call it again"
    *  (this from the doc on www.openssl.org and not the 
    *  man pages :-( )
    * Just put a count around it to make sure we don't hang
    */
   while((0 == rc) && (shutcount < 5))
      {
      rc = SSL_shutdown(conn->ssl);
      shutcount++;
      }
#  if defined(TLS_DEBUG)
   if (rc != 1)
      {
      tls_debug("SSL shutdown failed (final rc=%d).\n",rc);
      }
#  endif /* defined(TLS_DEBUG) */ 

    SSL_free(conn->ssl);
    conn->ssl = NULL;
    conn->sock = -1;
}

int tls_accept_ctrl(int s)
{
    int err;
    char *subject;
#  if defined(TLS_DEBUG)
   tls_debug("tls_accept_ctrl [%d]\n",s);
#  endif /* defined(TLS_DEBUG) */ 
	
    if (ctrl_conn.ssl) {
	syslog(LOG_ERR, "Already TLS connected!");
	return 1;
    }
    ctrl_conn.ssl = SSL_new(ssl_ctx);
    if (!ctrl_conn.ssl) {
	syslog(LOG_ERR, "SSL_new() %s", (char *)ERR_error_string(ERR_get_error(), NULL));
	return 2;
    }
    SSL_set_fd(ctrl_conn.ssl, s);
    ctrl_conn.sock = s;
    
  retry:
    err = SSL_accept(ctrl_conn.ssl);
    if (err < 1) {
	int ssl_err = SSL_get_error(ctrl_conn.ssl, err);
	syslog(LOG_ERR, "SSL_accept(): (%d) %s", ssl_err,
		(char *)ERR_error_string(ERR_get_error(), NULL));
	if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
	    goto retry;
	tls_close_session(&ctrl_conn);
	return 3;
    }
   
    subject = tls_get_subject_name(ctrl_conn.ssl);
    syslog(LOG_NOTICE, "TLS connection using cipher %s (%d bits)",
	   SSL_get_cipher(ctrl_conn.ssl), SSL_get_cipher_bits(ctrl_conn.ssl, NULL));
    if (subject)
	syslog(LOG_NOTICE, "Client: %s", subject);

    return 0;
}

int tls_accept_data(int s)
{
    int err;
    static int logged_data_connection = 0;
#  if defined(TLS_DEBUG)
   tls_debug("tls_accept_data [%d]\n",s);
#  endif /* defined(TLS_DEBUG) */ 
	
    if (data_conn.ssl) {
	syslog(LOG_ERR, "Already TLS connected!");
	return 1;
    }
    data_conn.ssl = SSL_new(ssl_ctx);
    if (!data_conn.ssl) {
	syslog(LOG_ERR, "SSL_new() %s", (char *)ERR_error_string(ERR_get_error(), NULL));
	return 2;
    }

    SSL_set_fd(data_conn.ssl, s);
    data_conn.sock = s;
    
  retry:
    err = SSL_accept(data_conn.ssl);
    if (err < 1) {
	int ssl_err = SSL_get_error(data_conn.ssl, err);
	syslog(LOG_ERR, "SSL_accept(): (%d) %s", ssl_err,
		(char *)ERR_error_string(ERR_get_error(), NULL));
	if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
	    goto retry;
	tls_close_session(&data_conn);
	return 3;
    }

    /* 
     * allow the option to only log first TLS data connection, 
     *  otherwise there might be lots of logging
     */
    if ((!logged_data_connection) || (tls_log_all_data))
       {
	syslog(LOG_NOTICE, "TLS data connection using cipher %s (%d bits)",
	       SSL_get_cipher(data_conn.ssl), SSL_get_cipher_bits(data_conn.ssl, NULL));
	logged_data_connection = 1;
    }
    return 0;
}

void tls_shutdown(void)
{
#  if defined(TLS_DEBUG)
   tls_debug("tls_shutdown\n");
#  endif /* defined(TLS_DEBUG) */ 
    if (data_conn.ssl) {
    	SSL_shutdown(data_conn.ssl);
	SSL_free(data_conn.ssl);
	data_conn.ssl = NULL;
	data_conn.sock = -1;
    }
    if (ctrl_conn.ssl) {
    	SSL_shutdown(ctrl_conn.ssl);
	SSL_free(ctrl_conn.ssl);
	ctrl_conn.ssl = NULL;
	ctrl_conn.sock = -1;
    }
}

void tls_cleanup(void)
{
#  if defined(TLS_DEBUG)
   tls_debug("tls_cleanup\n");
#  endif /* defined(TLS_DEBUG) */ 
    tls_shutdown();
    if (crl_store) {
    	X509_STORE_free(crl_store);
	crl_store = NULL;
    }
    if (ssl_ctx) {
	SSL_CTX_free(ssl_ctx);
	ssl_ctx = NULL;
    }
    if (tmp_dh) {
        DH_free(tmp_dh);
        tmp_dh = NULL;
    }
    if (tmp_rsa) {
        RSA_free(tmp_rsa);
        tmp_rsa = NULL;
    }
    ERR_free_strings();
    ERR_remove_state(0);
    EVP_cleanup();      /* release the stuff allocated by SSL_library_init() */
    if (tls_rsa_key_file) {
    	if (tls_rsa_key_file != tls_rsa_cert_file)
	    free(tls_rsa_key_file);
	tls_rsa_key_file = NULL;
    }
    if (tls_password) {
        free(tls_password);
        tls_password = NULL;
    }
    if (tls_rsa_cert_file) {
    	free(tls_rsa_cert_file);
	tls_rsa_cert_file = NULL;
    }
    if (tls_dsa_key_file) {
    	if (tls_dsa_key_file != tls_dsa_cert_file)
	    free(tls_dsa_key_file);
	tls_dsa_key_file = NULL;
    }
    if (tls_dsa_cert_file) {
    	free(tls_dsa_cert_file);
	tls_dsa_cert_file = NULL;
    }
    if (tls_dhparam_file) {
    	free(tls_dhparam_file);
	tls_dhparam_file = NULL;
    }
    if (tls_crl_file) {
    	free(tls_crl_file);
	tls_crl_file = NULL;
    }
    if (tls_crl_dir) {
    	free(tls_crl_dir);
	tls_crl_dir = NULL;
    }
    if (tls_cipher_list) {
    	free(tls_cipher_list);
	tls_cipher_list = NULL;
    }
    if (tls_rand_file)
	/* tls_rand_file is not malloc()'ed */
	RAND_write_file(tls_rand_file);
#  if defined(DEBUG_OPENSSL_MEM)
    {
    char fname[] = "/tmp/ftpd_memleak_XXXXXX";
    int fd;
    if ((fd = mkstemp(fname)) != -1) {
        FILE *f = fdopen(fd, "w");
        if (f) {
            CRYPTO_mem_leaks_fp(f);
            fclose(f);
        }
    }
    }
#  endif /* defined(DEBUG_OPENSSL_MEM) */ 
    if (tls_config_file) {
    	free(tls_config_file);
	tls_config_file = NULL;
    }
#  if defined(TLS_DEBUG)
    if(NULL != DEBUG_FILE)
       {
       time_t c_time;
       c_time = time(0);
       tls_debug("Tracing stopped on PID %d - %s",getpid(),ctime(&c_time));
       fclose(DEBUG_FILE);
       DEBUG_FILE = NULL;
       }
#  endif /* defined(TLS_DEBUG) */ 
	
    EVP_cleanup();
}

void handle_ssl_error(int error, char *where)
{
#  if defined(TLS_DEBUG)
   tls_debug("handle_ssl_error\n");
#  endif /* defined(TLS_DEBUG) */ 
    switch (error) {
    	case SSL_ERROR_NONE:
	    return;
	case SSL_ERROR_SSL:
	    syslog(LOG_ERR, "Panic: SSL_ERROR_SSL in %s!", where);
	    break;
	case SSL_ERROR_WANT_READ:
	    syslog(LOG_ERR, "Panic: SSL_ERROR_WANT_READ in %s!", where);
	    break;
	case SSL_ERROR_WANT_WRITE:
	    syslog(LOG_ERR, "Panic: SSL_ERROR_WANT_WRITE in %s!", where);
	    break;
	case SSL_ERROR_WANT_X509_LOOKUP:
	    syslog(LOG_ERR, "Panic: SSL_ERROR_WANT_X509_LOOKUP in %s!", where);
	    break;
	case SSL_ERROR_SYSCALL:
	    syslog(LOG_ERR, "Panic: SSL_ERROR_SYSCALL in %s!", where);
	    break;
	case SSL_ERROR_ZERO_RETURN:
	    syslog(LOG_ERR, "Panic: SSL_ERROR_ZERO_RETURN in %s!", where);
	    break;
	case SSL_ERROR_WANT_CONNECT:
	    syslog(LOG_ERR, "Panic: SSL_ERROR_WANT_CONNECT in %s!", where);
	    break;
	default:
	    syslog(LOG_ERR, "Panic: SSL_ERROR %d in %s!", error, where);
	    break;
    }
    /* if we reply() something here, we might just trigger another handle_ssl_error()
     * call and loop endlessly...
     */
    syslog(LOG_ERR, "Unexpected OpenSSL error, disconnected.");
    dologout(error);
    /* NOTREACHED */
}

ssize_t tls_read(int fd, void *buf, size_t count)
{
    SSL *ssl = SOCK_TO_SSL(fd);
#  if defined(TLS_DEBUG)
   tls_debug("tls_read [%d]\n",fd);
#  endif /* defined(TLS_DEBUG) */ 
    
    if (ssl) {
	ssize_t c = SSL_read(ssl, buf, count);
	if (c < 0) {
	    int err = SSL_get_error(ssl, c);
	    /* read(2) returns only the generic error number -1 */
	    c = -1;
	    switch (err) {
	    	case SSL_ERROR_WANT_READ:
		    /* simulate an EINTR in case OpenSSL wants to read more */
		    errno = EINTR;
		    break;
		case SSL_ERROR_SYSCALL:
		    /* don't know what this is about */
		    break;
		default:
		    handle_ssl_error(err, "tls_read()");
		    break;
	    }
	}
#  if defined(TLS_DEBUG)
        {
        unsigned char *ptr = NULL; 
        if(c > 0) 
           {
           ptr = malloc(c + 1);
           if (ptr != NULL)
              {
              int loop;
              memset(ptr,'\0',c+1);
              memcpy(ptr,buf,c);
              for(loop=0; loop < c; loop++)
                 ptr[loop] = isprint(ptr[loop]) ? ptr[loop] : '.' ;
              tls_debug("             got (%s)\n",ptr);
              free(ptr);
              }
           else
              {
              tls_debug("             got MALLOC_ERR\n");
              }
           }
        else
           {
           tls_debug("             got ()\n");
           }
        }
#  endif /* defined(TLS_DEBUG) */ 
	return c;
    }
    else
	return read(fd, buf, count);
}

ssize_t tls_write(int fd, const void *buf, size_t count)
{
    SSL *ssl = SOCK_TO_SSL(fd);
#  if defined(TLS_DEBUG)
        {
        unsigned char *ptr = NULL; 
        size_t c;
        c = count;
        if(c > 0) 
           {
           ptr = malloc(c + 1);
           if (ptr != NULL)
              {
              int loop;
              memset(ptr,'\0',c+1);
              memcpy(ptr,buf,c);
              for(loop=0; loop < c; loop++)
                 ptr[loop] = isprint(ptr[loop]) ? ptr[loop] : '.' ;
              tls_debug("tls_write [%d] (%s)\n",fd,ptr);
              free(ptr);
              }
           else
              {
              tls_debug("tls_write [%d] MALLOC_ERR\n",fd);
              }
           }
        else
           {
           tls_debug("tls_write [%d] ()\n",fd);
           }
        }
#  endif /* defined(TLS_DEBUG) */ 
    
    if (ssl) {
    	ssize_t c = SSL_write(ssl, buf, count);
	if (c < 0) {
	    int err = SSL_get_error(ssl, c);
	    /* write(2) returns only the generic error number -1 */
	    c = -1;
	    switch (err) {
	        case SSL_ERROR_WANT_WRITE:
	    	    /* simulate an EINTR in case OpenSSL wants to write more */
		    errno = EINTR;
		    break;
		case SSL_ERROR_SYSCALL:
		    /* don't know what this is about */
		    break;
		default:
		    handle_ssl_error(err, "tls_write()");
		    break;
	    }
	}
	return c;
    }	
    else
	return write(fd, buf, count);
}

#  if defined(TLS_STDC)
int tls_fprintf(FILE *stream, const char *fmt, ...)
#  else /* !(defined(TLS_STDC)) */ 
int tls_fprintf(stream, fmt, va_alist)
    FILE *stream;
    char *fmt;
    va_dcl
#  endif /* !(defined(TLS_STDC)) */ 
{
    va_list ap;
#  if defined(TLS_DEBUG)
   tls_debug("tls_fprintf [%d] (%s)\n",fileno(stream),fmt);
#  endif /* defined(TLS_DEBUG) */ 
    
#  if defined(TLS_STDC)
    va_start(ap, fmt);
#  else /* !(defined(TLS_STDC)) */ 
    va_start(ap);
#  endif /* !(defined(TLS_STDC)) */ 
    return tls_vfprintf(stream, fmt, ap);
}

int tls_vfprintf(FILE *stream, const char *format, va_list ap)
{
#  define SNP_MAXBUF 1024000
    SSL *ssl = SOCK_TO_SSL(fileno(stream));
#  if defined(TLS_DEBUG)
   tls_debug("tls_vfprintf [%d] (%s)\n",fileno(stream),format);
#  endif /* defined(TLS_DEBUG) */ 

    if (ssl) {
	/* here I boldly assume that snprintf() and vsnprintf() uses the same
	 * return value convention. if not, what kind of libc is this? ;-)
	 */
	char sbuf[1024] = { 0 }, *buf = sbuf, *lbuf = NULL;
	int sent = 0, size, ret, w;
	ret = vsnprintf(sbuf, sizeof(sbuf), format, ap);
#  if defined(SNPRINTF_OK)
	/* this one returns the number of bytes it wants to write in case of overflow */
	if (ret >= sizeof(sbuf) && ret < SNP_MAXBUF) {
	    /* sbuf was too small, use a larger lbuf */
	    lbuf = malloc(ret + 1);
	    if (lbuf) {
		vsnprintf(lbuf, ret + 1, format, ap);
		buf = lbuf;
	    }
	}
#  else /* !(defined(SNPRINTF_OK)) */ 
#    if defined(SNPRINTF_HALFBROKEN)
	/* this one returns the number of bytes written (excl. \0) in case of overflow */
#      define SNP_OVERFLOW(x, y) ( x == y ? 1 : 0 )
#      define SNP_NOERROR(x)     ( x < 0 ? 0 : 1 )
#    else /* !(defined(SNPRINTF_HALFBROKEN)) */ 
#      if defined(SNPRINTF_BROKEN)
	/* this one returns -1 in case of overflow */
#        define SNP_OVERFLOW(x, y) ( x < 0 ? 1 : 0 )
#        define SNP_NOERROR(x)     ( 1 )  /* if -1 means overflow, what's the error indication? */
#      else /* !(defined(SNPRINTF_BROKEN)) */ 
#        error No valid SNPRINTF_... macro defined!
#      endif /* !(defined(SNPRINTF_BROKEN)) */ 
#    endif /* !(defined(SNPRINTF_HALFBROKEN)) */ 
	if (SNP_NOERROR(ret) && SNP_OVERFLOW(ret, sizeof(sbuf) - 1)) {
	    /* sbuf was too small, use a larger lbuf */
	    size = sizeof(sbuf);
	    do {
		if ((size *= 2) > SNP_MAXBUF)	/* try to double the size */
		    break;
		if (lbuf) free(lbuf);
		lbuf = malloc(size);
		if (lbuf) {
		    ret = vsnprintf(lbuf, size, format, ap);
		    buf = lbuf;
		} else
		    break;
	    } while (SNP_NOERROR(ret) && SNP_OVERFLOW(ret, size - 1));
	}
#  endif /* !(defined(SNPRINTF_OK)) */ 
	size = strlen(buf);
	do {
	    w = tls_write(fileno(stream), buf + sent, size - sent);
	    if (w > 0)
		sent += w;
	    else if (!(w < 0 && errno == EINTR))
		break;	/* other error than EINTR or w == 0 */
        } while (sent != size);
	if (lbuf) free(lbuf);
	return sent;
    } else {
	return vfprintf(stream, format, ap);
    }
}

#  if defined(TLS_STDC)
int tls_printf(const char *fmt, ...)
#  else /* !(defined(TLS_STDC)) */ 
int tls_printf(fmt, va_alist)
    char *fmt;
    va_dcl
#  endif /* !(defined(TLS_STDC)) */ 
{
    va_list ap;
#  if defined(TLS_DEBUG)
   tls_debug("tls_printf [%d] (%s)\n",fileno(stdout),fmt);
#  endif /* defined(TLS_DEBUG) */ 
#  if defined(TLS_STDC)
    va_start(ap, fmt);
#  else /* !(defined(TLS_STDC)) */ 
    va_start(ap);
#  endif /* !(defined(TLS_STDC)) */ 
    return tls_vfprintf(stdout, fmt, ap);
}

int tls_vprintf(const char *format, va_list ap)
{
#  if defined(TLS_DEBUG)
   tls_debug("tls_vprintf [%d] (%s)\n",fileno(stdout),format);
#  endif /* defined(TLS_DEBUG) */ 
    return tls_vfprintf(stdout, format, ap);
}

int tls_fgetc(FILE *stream)
{
    SSL *ssl = SOCK_TO_SSL(fileno(stream));
#  if defined(TLS_DEBUG)
   tls_debug("tls_fgetc [%d]\n",fileno(stream));
#  endif /* defined(TLS_DEBUG) */ 

    if (ssl) {
	unsigned char r;
	int err;
	do
	    err = tls_read(fileno(stream), &r, 1);
	while (err < 0 && errno == EINTR);
	if (err == 1)
           {
#  if defined(TLS_DEBUG)
        tls_debug("              got (%02X '%c')\n",r,isprint(r) ? r : '.');
#  endif /* defined(TLS_DEBUG) */ 
	    return (int) r;
            }
	else
           {
#  if defined(TLS_DEBUG)
        tls_debug("              got (EOF)\n");
#  endif /* defined(TLS_DEBUG) */ 
	    return EOF;
            }
    } else {
       int inchar;
       inchar = fgetc(stream);
#  if defined(TLS_DEBUG)
        tls_debug("              got (%02X '%c')\n",
	           inchar,
		   isprint(inchar) ? inchar : '.');
#  endif /* defined(TLS_DEBUG) */ 
       return(inchar);
    }
}

int tls_fputc(int c, FILE *stream)
{
   SSL *ssl = SOCK_TO_SSL(fileno(stream));

#  if defined(TLS_DEBUG)
   tls_debug("tls_fputc [%d] (%02X '%c')\n",fileno(stream),c,isprint(c) ? c : '.');
#  endif /* defined(TLS_DEBUG) */ 

    if (ssl) {
	unsigned char uc = c;
	int err = 1;
	do
            {
#if defined(BUFFER_TLS_PUTC)
            if(fileno(stream) == fileno(stdout))
               {
               err = tls_write(fileno(stream), &uc, 1);
               }
            else
               {
               if(err == 1)
                  fputc_buffer[fputc_buflen++] = uc;
               if(fputc_buflen >= PUTC_BUFFERSIZE)
                  {
                  err = tls_write(fileno(stream), fputc_buffer, fputc_buflen);
   #  if defined(TLS_DEBUG)
                  tls_debug("tls_fputc [%d] %d/%d written\n",fileno(stream),err,fputc_buflen);
   #  endif /* defined(TLS_DEBUG) */ 
                  if(err > 0)
                     err = 1;
                  if(err >= 0 || errno != EINTR)
                     {
                     fputc_buflen = 0;
                     memset(fputc_buffer,'\0',sizeof(fputc_buffer));
                     }
                  }
               }
#else /* !defined(BUFFER_TLS_PUTC) */
	    err = tls_write(fileno(stream), &uc, 1);
#endif /* !defined(BUFFER_TLS_PUTC) */
            }
	while (err < 0 && errno == EINTR);
	if (err == 1)
	    return (int) uc;
	else
	    return EOF;
    } else
	return fputc(c, stream);
}

#if defined(BUFFER_TLS_PUTC)
void tls_fputc_flush(int fd)
{
   if((fputc_buflen > 0) && (fd != fileno(stdout)))
      {
      int wrote;
      wrote = tls_write(fd, fputc_buffer, fputc_buflen);
#  if defined(TLS_DEBUG)
      tls_debug("tls_fputc_flush [%d] %d/%d written\n",fd,wrote,fputc_buflen);
#  endif /* defined(TLS_DEBUG) */ 
      fputc_buflen = 0;
      memset(fputc_buffer,'\0',sizeof(fputc_buffer));
      }

  return;
}
#endif /* defined(BUFFER_TLS_PUTC) */

int tls_fputs(const char *s, FILE *stream)
{
    SSL *ssl = SOCK_TO_SSL(fileno(stream));
#  if defined(TLS_DEBUG)
   tls_debug("tls_fputs %d (%s)\n",fileno(stream),s);
#  endif /* defined(TLS_DEBUG) */ 

    if (ssl) {
	int err;
	do
	    err = tls_write(fileno(stream), s, strlen(s));
	while (err < 0 && errno == EINTR);
	if (err >= 1)
	    return strlen(s);
	else
	    return EOF;
    } else
	return fputs(s, stream);
}

int tls_fclose(FILE *stream)
{
#  if defined(TLS_DEBUG)
    tls_debug("tls_fclose [%d]\n",fileno(stream));
#  endif /* defined(TLS_DEBUG) */ 
    return(tls_close(fileno(stream)));
}

int tls_close(int fd)
{
    SSL *ssl = SOCK_TO_SSL(fd);
#  if defined(TLS_DEBUG)
   tls_debug("tls_close [%d]\n",fd);
#  endif /* defined(TLS_DEBUG) */ 
   if(fd > 0) {
      if (ssl) {
         (void) signal(SIGPIPE,SIG_IGN);
#if defined(BUFFER_TLS_PUTC)
         if(fileno(stdout) != fd)
            {
            tls_fputc_flush(fd);
            }
#endif /* defined(BUFFER_TLS_PUTC) */
         SSL_shutdown(ssl);
         SSL_free(ssl);
         (void) signal(SIGPIPE,lostconn);
         if (ssl == data_conn.ssl) {
            data_conn.ssl = NULL;
            data_conn.sock = -1;
         } else if (ssl == ctrl_conn.ssl) {
            ctrl_conn.ssl = NULL;
            ctrl_conn.sock = -1;
         }
      }
      return close(fd);
   } else {
   return(0);
   }
}

int tls_fflush(FILE *stream)
{
#  if defined(TLS_DEBUG)
   tls_debug("tls_fflush [%d] ",fileno(stream));
#  endif /* defined(TLS_DEBUG) */ 
    if (stream == NULL)
	return fflush(NULL);
    if (SOCK_TO_SSL(fileno(stream)))
        {
#if defined(BUFFER_TLS_PUTC)
        if(fileno(stdout) != fileno(stream))
           {
           tls_fputc_flush(fileno(stream));
           }
#endif /* defined(BUFFER_TLS_PUTC) */
	return 0;	/* don't do anything! */
        }
    else
	return fflush(stream);
}

char *file_fullpath(char *fn)
{
    static char fp[256];
    FILE *file;
    char *dir;
    
    /* check if it is a full path already */
    if ((strchr(fn, '/'))) {
	if ((file = fopen(fn, "r"))) {
	    fclose(file);
	    return fn;
	}
	else
	    return NULL;
    }
    /* check if it is in current dir */
    if ((file = fopen(fn, "r"))) {
    	fclose(file);
	return fn;
    }
    if (!(dir = getenv(X509_get_default_cert_dir_env())))	/* $SSL_CERT_DIR */
    	dir = (char *)X509_get_default_cert_dir();
    snprintf(fp, sizeof(fp), "%s/%s", dir, fn);
    if ((file = fopen(fp, "r"))) {
    	fclose(file);
	return fp;
    }
    dir = (char *)X509_get_default_private_dir();
    snprintf(fp, sizeof(fp), "%s/%s", dir, fn);
    if ((file = fopen(fp, "r"))) {
    	fclose(file);
	return fp;
    }
    return NULL;
}

void tls_load_config_file(void)
   {
   FILE *ConfigFile = NULL;
   char buffer[1024];
   if((tls_config_file) && (strlen(tls_config_file) != 0))
      {
      syslog(LOG_INFO,"wu-ftpd - loading TLS config file [%s]",tls_config_file);
      ConfigFile = fopen(tls_config_file,"r");
      if(ConfigFile != NULL)
         {
         memset(buffer,'\0',sizeof(buffer));
         while(NULL != fgets(buffer,sizeof(buffer)-1,ConfigFile))
            {
            if(strlen(buffer) > 0)
               {
               while(strchr(" \t\n\r",buffer[strlen(buffer) - 1]))
                  buffer[strlen(buffer) - 1] = '\0';
               if(strlen(buffer) > 0)
                  {
#  if defined(TLS_DEBUG)
                  tls_debug("ConfigFile [%s]\n",buffer);
#  endif /* defined(TLS_DEBUG) */ 
                  if('#' != buffer[0])
                     {
                     tls_optarg(buffer,TLS_OPTARG_FILE);
                     }
                  }
               }
            memset(buffer,'\0',sizeof(buffer));
            }
         fclose(ConfigFile);
         ConfigFile = NULL;
         }
      else
         {
         syslog(LOG_ERR,"wu-ftpd - could not open TLS config file [%s]",tls_config_file);
         }
      }
   return;
   }

void tls_start_debugging(void)
   {
#  if defined(TLS_DEBUG)
   time_t c_time;
   syslog(LOG_NOTICE,"wu-ftpd TLS_DEBUG - tracing into %s",tls_debug_filename);
   if(NULL == DEBUG_FILE)
      {
      DEBUG_FILE = fopen(tls_debug_filename,"w");
      }
   c_time = time(0);
   tls_debug("Tracing started on PID %d - %s",getpid(),ctime(&c_time));
#  else /* !(defined(TLS_DEBUG)) */ 
   syslog(LOG_NOTICE,"wu-ftpd TLS_DEBUG - not supported by binary");
#  endif /* !(defined(TLS_DEBUG)) */ 
   return;
   }

void tls_check_option_consistency(void)
   {
   /*
    * THIS FUNCTION MUST BE CALLED ONCE ALL PARMS ARE PROCESSED
    * =========================================================
    */
   /* 
    * Check parameter/flag consistency
    *
    * tls_only_client_cert_auth forces:
    *   tls_protect_user
    *   tls_authentication_mode to TLS_AUTH_CLIENT_MUST
    *
    * tls_force_data_prot_p forces:
    *   tls_protect_user
    */
   if(1 == tls_dont_use_tls)
      {
      if(1 == tls_protect_user)
         {
         syslog(LOG_NOTICE,"ftp-tls: notls forced tlsonly off");
         tls_protect_user = 0;
         }
      if(1 == tls_only_client_cert_auth)
         {
         syslog(LOG_NOTICE,"ftp-tls: notls forced clientcert off");
         tls_only_client_cert_auth = 0;
         }
      if(1 == tls_force_data_prot_p)
         {
         syslog(LOG_NOTICE,"ftp-tls: notls forced tlsdata off");
         tls_force_data_prot_p = 0;
         }
      }
   if(1 == tls_only_client_cert_auth)
      {
      if(0 == tls_protect_user)
         {
         syslog(LOG_NOTICE,"ftp-tls: clientcert forced tlsonly"); 
         tls_protect_user = 1;
         }
      if(TLS_AUTH_CLIENT_MUST != tls_authentication_mode)
         {
         syslog(LOG_NOTICE,"ftp-tls: clientcert forced authmode=client_must"); 
         tls_authentication_mode = TLS_AUTH_CLIENT_MUST;
         }
      }
   if(1 == tls_force_data_prot_p)
      {
      if(0 == tls_protect_user)
         {
         syslog(LOG_NOTICE,"ftp-tls: tlsdata forced tlsonly"); 
         tls_protect_user = 1;
         }
      }

   /*
    * place out TLS specific requirements into the higher security
    *  abstraction layer
    */

   if(0 == tls_dont_use_tls)
      {
      sec_add_mechanism(SEC_MECHANISM_TLS);
      }
   if(1 == tls_protect_user)
      {
      set_control_policy(SEC_CTRL_PROTECT_USER);
      }

   return;
   }

void tls_log_options(void)
   {
   syslog(LOG_INFO, 
          "wu-ftpd - TLS settings: control %s, client_cert %s, data %s",
          (tls_protect_user) ? "force" : "allow",
          (tls_only_client_cert_auth) ? "force" : "allow",
          (tls_force_data_prot_p) ? "force" : "allow");

#  if defined(TLS_DEBUG)
   tls_debug("wu-ftpd - [rsa]key_file [%s] (%s)\n",
	     tls_rsa_key_file,
	     (SSL_FILETYPE_PEM == tls_rsa_format) ? "PEM" : "DER");
   tls_debug("wu-ftpd - password [%s]\n",tls_password);
   tls_debug("wu-ftpd - [rsa]cert_file [%s] (%s)\n", 
	     tls_rsa_cert_file,
	     (SSL_FILETYPE_PEM == tls_rsa_format) ? "PEM" : "DER");
   tls_debug("wu-ftpd - [dsa]key_file [%s]\n",tls_dsa_key_file);
   tls_debug("wu-ftpd - [dsa]cert_file [%s]\n",tls_dsa_cert_file);
   tls_debug("wu-ftpd - CApath [%s]\n",tls_CApath);
   tls_debug("wu-ftpd - CAfile [%s]\n",tls_CAfile);
   tls_debug("wu-ftpd - crl_file [%s]\n",tls_crl_file);
   tls_debug("wu-ftpd - crl_dir [%s]\n",tls_crl_dir);
   tls_debug("wu-ftpd - dhparam_file [%s]\n",tls_dhparam_file);
   tls_debug("wu-ftpd - rand_file [%s]\n",tls_rand_file);
   tls_debug("wu-ftpd - cipher_list [%s]\n",tls_cipher_list);
   tls_debug("wu-ftpd - debug_filename [%s]\n",tls_debug_filename);
   tls_debug("wu-ftpd - system_certdir [%s]\n",tls_system_certdir);
   tls_debug("wu-ftpd - config_file [%s]\n",(NULL == tls_config_file) ? "" : tls_config_file);
   tls_debug("wu-ftpd - TLS settings: certsok %s, debug %s\n",
             (tls_no_verify) ? "true" : "false",
             (tls_debug) ? "on" : "off");
   tls_debug("wu-ftpd - TLS settings: control %s, client_cert %s, data %s\n",
             (tls_protect_user) ? "force" : "allow",
             (tls_only_client_cert_auth) ? "force" : "allow",
             (tls_force_data_prot_p) ? "force" : "allow");
   tls_debug("wu-ftpd - TLS settings: allow_auth_ssl %s, auth_ssl_reply %s\n",
             (tls_allow_auth_ssl) ? "true" : "false",
             (tls_bad_auth_ssl_reply) ? "334" : "234");
   tls_debug("wu-ftpd - authmode [%s], ccc %s, logdata %s\n",
             ((TLS_AUTH_SERVER == tls_authentication_mode) ? "server" :
              ((TLS_AUTH_CLIENT_CAN == tls_authentication_mode) ?
               "client_can" : "client_must")),
             (tls_allow_ccc) ? "allow" : "deny",
             (tls_log_all_data) ? "all" : "first tls");
   tls_debug("wu-ftpd - certpass [%s]\n",
             ((TLS_CERTPASS_NOPASS == tls_certpass_mode) ? "certok" :
               "needpass" ));
   tls_debug("wu-ftpd - and, finally, TLS is%sbeing used\n",
             (tls_dont_use_tls) ? " not " : " ");
#  endif /* defined(TLS_DEBUG) */ 
   return;
   }

#  if defined(TLS_STDC)
int tls_debug(const char *fmt, ...)
#  else /* !(defined(TLS_STDC)) */ 
int tls_debug(fmt, va_alist)
    char *fmt;
    va_dcl
#  endif /* !(defined(TLS_STDC)) */ 
   {
   int rc = 0;
#  if defined(TLS_DEBUG)
   va_list ap;
   int serrno;
    
   serrno = errno;
#    if defined(TLS_STDC)
   va_start(ap, fmt);
#    else /* !(defined(TLS_STDC)) */ 
   va_start(ap);
#    endif /* !(defined(TLS_STDC)) */ 
   if(NULL != DEBUG_FILE)
       {
       fprintf(DEBUG_FILE,"[%06d] ",getpid());
       vfprintf(DEBUG_FILE,fmt,ap);
       fflush(DEBUG_FILE);
       }
   errno = serrno;
#  endif /* defined(TLS_DEBUG) */ 
   return(rc);
   }

int tls_check_data_prot(const char *parm, int ftpCommand)
   {
   int rc = 0;
   char ActionType;

   switch(ftpCommand)
      {
      case SEC_CMD_STOR:
      case SEC_CMD_STOU:
      case SEC_CMD_APPE:
         ActionType = 'w';
         break;
      case SEC_CMD_LIST:
      case SEC_CMD_NLST:
         ActionType = 'l';
         break;
      case SEC_CMD_RETR:
         ActionType = 'r';
         break;
      default:
         ActionType = 'x';
      }

#  if defined(TLS_DEBUG)
   tls_debug("tls_check_data_prot [%s] [%c] (%s)\n",
             parm,
             ActionType,
             get_data_prot_string());
#  endif /* defined(TLS_DEBUG) */

   if(tls_force_data_prot_p && ('P' != get_data_prot_level()))
      {
      rc = 0;
      }
   else
      {
      rc = 1;
      }

   return(rc);
   }

int tls_is_ccc_allowed( void )
   {
   return(tls_allow_ccc);
   }

int tls_is_pass_allowed( void )
   {
   return((1 == tls_only_client_cert_auth) ? 0 : 1);
   }


void tls_ccc( void )
   {
#  if defined(TLS_DEBUG)
   tls_debug("tls_ccc - shutting down SSL session on control connection!!\n");
#  endif /* defined(TLS_DEBUG) */ 

   tls_close_session(&ctrl_conn);

   syslog(LOG_NOTICE, "TLS no longer protecting control connection at client request\n");

   return;
   }

int tls_hack_allow_auth_ssl( void )
   {
   return(tls_allow_auth_ssl);
   }

int tls_hack_bad_auth_ssl_reply( void )
   {
   return(tls_bad_auth_ssl_reply);
   }

int tls_allow_autologin( void )
   {
   int autolog = 1;
   switch(tls_certpass_mode)
      {
      case TLS_CERTPASS_NOPASS:
         autolog = 1;
         break;
      case TLS_CERTPASS_REQUIRE:
         autolog = 0;
         break;
      default:;
      }
   return(autolog);
   }

#endif /* defined(USE_TLS) */ 
