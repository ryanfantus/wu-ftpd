/*
 * Copyright (c) 2004 pfh
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
 */

#if !defined(_SECUTIL_H_)
#  define _SECUTIL_H_
#if defined(USE_TLS) || defined(USE_GSS)
#define USE_SECURITY 1 /*
                        * use this as the define to see in any security
                        * mechanism is being supported
                        */

#  if defined(__STDC__)
#    define TLS_STDC 1
#  endif /* defined(__STDC__) */ 
#  define TLS_STDC 1

/*
 * these are the mechanisms supported (which may map to multiple 
 *  parameters to AUTH)
 *
 * SEC_MECHANISM_TLS     - "TLS", "TLS-C", "TLS-C", "SSL"
 * SEC_MECHANISM_GSS     - "GSSAPI"
 *
 * they are set bitwise by the sec_add_supported_mechanism() call
 *  and checked for with the sec_check_mechanism() call.
 */

#define SEC_MECHANISM_NONE   0x00000000
#define SEC_MECHANISM_TLS    0x00000001
#define SEC_MECHANISM_GSS    0x00000002

/*
 * SEC_CTRL_NOT_YET_PROTECTED - this is the initial state and means that 
 *                              the control connection is in plaintext.
 * SEC_CTRL_TLS_PROTECTED     - this means that an "AUTH TLS" or "AUTH SSL"
 *                              command (and the subsequent TLS/SSL handshake)
 *                              have been completed and no "CCC" command has 
 *                              been actioned.
 * SEC_CTRL_GSS_PROTECTED     - this means user has successfully authenticated
 *                              with GSSAPI and is protecting the control
 *                              channel.
 * SEC_CTRL_CLEARED           - this means that an AUTH mechanism has been
 *                              used and then cleared by a subsequent 
 *                              "CCC" exchange.
 */

#define SEC_CTRL_NOT_YET_PROTECTED  0
#define SEC_CTRL_TLS_PROTECTED      1
#define SEC_CTRL_GSS_PROTECTED      2
#define SEC_CTRL_CLEARED            3

/*
 * SEC_CTRL_NO_RESTRICTIONS - the 'USER' command is allowed over an
 *                            insecure connection
 * SEC_CTRL_PROTECT_USER    - the 'USER' command is only allowed on 
 *                            connections that are secured
 */

#define SEC_CTRL_NO_RESTRICTIONS  0
#define SEC_CTRL_PROTECT_USER     1

/*
 * SEC_AUTH_ALLOWED_BY_PASS - the 'PASS' command is allowed for authentication
 * SEC_AUTH_REQUIRE_STRONG  - the "AUTH" mechanism has a strong 
 *                            authentication mechanism which _must_ be
 *                            used.  The PASS command is never requested nor
 *                            accepted.
 * SEC_AUTH_REQUIRE_BOTH    - the "AUTH" mechanism has a strong 
 *                            authentication mechanism which _must_ be
 *                            used.  The PASS command also required
 */

#define SEC_AUTH_ALLOWED_BY_PASS 0
#define SEC_AUTH_REQUIRE_STRONG  1
#define SEC_AUTH_REQUIRE_BOTH    2

/*
 * SEC_CCC_ALLOWED     - the 'CCC' command is allowed in an appropriate
 *                       place in the session
 * SEC_CCC_DISALLOWED  - the 'CCC' command is not allowed
 */

#define SEC_CCC_ALLOWED           0
#define SEC_CCC_DISALLOWED        1

/*
 * these defines are done per protection setting
 *  they govern the policy that will be implemented when checking 
 *  if a data connection should be allowed.
 */

#define SEC_DATA_PROT_ALLOWED       0
#define SEC_DATA_PROT_NOT_ALLOWED   1

/*
 * SEC_DATA_MECHANISM_PLAIN - data connections will be in plaintext
 * SEC_DATA_MECHANISM_TLS   - data connections will be protected with TLS
 * SEC_DATA_MECHANISM_GSS   - data connections will be protected with GSS
 */

#define SEC_DATA_MECHANISM_PLAIN 0
#define SEC_DATA_MECHANISM_TLS   1
#define SEC_DATA_MECHANISM_GSS   2

/*
 * defines for the is_data_connection_secure_enough() call
 */
#define SEC_CMD_STOR          1
#define SEC_CMD_STOU          2
#define SEC_CMD_RETR          3
#define SEC_CMD_NLST          4
#define SEC_CMD_LIST          5
#define SEC_CMD_APPE          6

/*
 * function prototypes
 */
void sec_add_mechanism(unsigned long MechanismType);
int sec_check_mechanism(unsigned long MechanismType);

void set_control_policy(int SecurityType);
int get_control_policy( void );

int get_auth_policy( void );

int get_ccc_policy( void );

void set_control_security(int SecurityType);
int get_control_security( void );

void set_data_prot_level(unsigned char ProtLevel);
unsigned char get_data_prot_level( void );
unsigned char *get_data_prot_string( void );

void set_data_prot_mechanism(int SecurityType);
int get_data_prot_mechanism( void );
int is_data_connection_secure_enough(const char *parm, int ftpCommand);

#endif /* defined(USE_TLS) || defined(USE_GSS) */ 
#endif /* !defined(_SECUTIL_H_) */ 
