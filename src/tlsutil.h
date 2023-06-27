/*
 * Copyright (c) 2000 Peter 'Luna' Runestig <peter@runestig.com>
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
 * $Id: tlsutil.h,v 1.6 2011/10/20 22:58:11 wmaton Exp $
 */

#if !defined(_TLSUTIL_H_)
#  define _TLSUTIL_H_

#include "secutil.h"

#  if defined(__STDC__)
#    define TLS_STDC 1
#  endif /* defined(__STDC__) */ 
#  define TLS_STDC 1

extern char 	*tls_rsa_key_file;
extern char	*tls_rsa_cert_file;
extern char 	*tls_dsa_key_file;
extern char	*tls_dsa_cert_file;
extern char	*tls_crl_file;
extern char	*tls_dhparam_file;
extern char	*tls_cipher_list;

int	tls_init(void);
void	tls_optarg(char *optarg,int parmOrFile);
void tls_update_parm(char **tag, char *value, int parmOrFile, int *parmFlag);
int	tls_accept_ctrl(int s);
int	tls_accept_data(int s);
void	tls_cleanup(void);
ssize_t	tls_read(int fd, void *buf, size_t count);
ssize_t	tls_write(int fd, const void *buf, size_t count);
char	*tls_userid_from_client_cert(void);
int	tls_is_user_valid(char *user);
void	tls_set_defaults(void);
int	tls_vfprintf(FILE *stream, const char *format, va_list ap);
int	tls_vprintf(const char *format, va_list ap);
int	tls_fflush(FILE *stream);
int	tls_fclose(FILE *stream);
int	tls_close(int fd);
int	tls_fgetc(FILE *stream);
int	tls_fputc(int c, FILE *stream);
#  if defined(TLS_STDC)
int	tls_fprintf(FILE *stream, const char *fmt, ...);
#  else /* !(defined(TLS_STDC)) */ 
int	tls_fprintf(stream, fmt, va_alist);
    FILE *stream;
    char *fmt;
    va_dcl
#  endif /* !(defined(TLS_STDC)) */ 
#  if defined(TLS_STDC)
int	tls_printf(const char *fmt, ...);
#  else /* !(defined(TLS_STDC)) */ 
int	tls_printf(fmt, va_alist);
    char *fmt;
    va_dcl
#  endif /* !(defined(TLS_STDC)) */ 
int tls_fputs(const char *s, FILE *stream);

#  if defined(TLS_STDC)
int	tls_debug(const char *fmt, ...);
#  else /* !(defined(TLS_STDC)) */ 
int	tls_debug(fmt, va_alist);
    char *fmt;
    va_dcl
#  endif /* !(defined(TLS_STDC)) */ 

int tls_check_data_prot(const char *parm, int ftpCommand);
int tls_is_ccc_allowed( void );
int tls_is_pass_allowed( void );
void tls_check_option_consistency(void);
void tls_log_options(void);
void tls_ccc( void );
int tls_hack_allow_auth_ssl( void );
int tls_hack_bad_auth_ssl_reply( void );
int tls_allow_autologin( void );

#  define TLS_OPTARG_PARM       1
#  define TLS_OPTARG_FILE       2

#endif /* !defined(_TLSUTIL_H_) */ 
