/*
 * Copyright (c) 2004, pfh
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
 * $Id: secutil.c,v 1.5 2011/10/20 22:58:11 wmaton Exp $
 */

#include "config.h"
#include "secutil.h"

#if defined(USE_SECURITY)

#if defined (USE_GSS)
#include "gssutil.h"
    extern gss_info_t gss_info;
#endif /* USE_GSS */
/*
 * these functions manage the server's view of the security state of
 *  the control and data connections.  They are called from various
 *  places (ftpcmd.y, ftpd.c, tlsutil.c, ... to get and set the status
 *  of various conceptual security constructs
 *
 * The idea is that they provide the layer of abstraction to allow
 *  multiple security mechanisms to co-exist.  As an overview, any new 
 *  mechanism will need to set the policies depending on their 
 *  configuration using ...
 *
 *  sec_add_mechanism()
 *  set_control_policy()
 *
 * They will also need to provide mechanism specific decisions in the 
 *  following functions ... 
 *
 *  get_auth_policy()
 *  get_ccc_policy()
 *  is_data_connection_secure_enough()
 *
 *  and will need to maintain the current security state of the control 
 *   and data connections with ...
 *
 *  set_control_security()
 *  set_data_prot_current()
 *
 *  they may need to modify the checks where get_control_security() is called
 *   to ensure that their new SEC_CTRL_XXX_PROTECTED is processed 
 *   correctly.
 *
 *  and, of course, they'll need to implement their security mechanism. 
 */

/*
 * allow the processing of the AUTH command to be simplified
 */

static unsigned long SupportedMechanisms = 0x00000000;

void sec_add_mechanism(unsigned long MechanismType)
   {
   SupportedMechanisms |= MechanismType;
   return;
   }

int sec_check_mechanism(unsigned long MechanismType)
   {
   int rc = 0;
   if((SupportedMechanisms & MechanismType) != 0x00000000)
      {
      rc = 1;
      }
   return(rc);
   }


/*
 * these function will get/set the current status of the 
 * control connection.  see secutil.h for descriptions
 */

static int control_security = SEC_CTRL_NOT_YET_PROTECTED;
static unsigned long AuthMechanism = 0x00000000;

void set_control_security(int SecurityType)
   {
   /*
    * we need to locally remember what AUTH mechanism 
    *  we are using, so that we can offer the ability for
    *  each AUTH mecahnism to implement their own controls
    *  (e.g. in is_data_connection_secure_enough())
    * - using control_security is not good enough because
    *  the 'CCC' processing may reset it.
    */
   switch(SecurityType)
      {
      case SEC_CTRL_TLS_PROTECTED:
         AuthMechanism = SEC_MECHANISM_TLS;
         break;
      case SEC_CTRL_GSS_PROTECTED:
         AuthMechanism = SEC_MECHANISM_GSS;
         break;
      default:;
      }

   control_security = SecurityType;
   return;
   }

int get_control_security( void )
   {
   return(control_security);
   }

/*
 * these function will get/set the policy of the 
 * control connection.  see secutil.h for descriptions
 */

static int control_policy = SEC_CTRL_NO_RESTRICTIONS;

void set_control_policy(int SecurityType)
   {
   control_policy = SecurityType;
   return;
   }

int get_control_policy( void )
   {
   return(control_policy);
   }
/*
 * these function will get the policy of the server towards 
 *  PASS.  see secutil.h for descriptions
 */

int get_auth_policy( void )
   {
   int policy = SEC_AUTH_REQUIRE_STRONG;
   switch(AuthMechanism)
      {
      case SEC_MECHANISM_NONE:
         policy = SEC_AUTH_ALLOWED_BY_PASS;
         break;
#if defined (USE_GSS)
      case SEC_MECHANISM_GSS:
         policy = SEC_AUTH_ALLOWED_BY_PASS;
         break;
#endif /* USE_GSS */
#if defined (USE_TLS)
      case SEC_MECHANISM_TLS:
         if(1 == tls_is_pass_allowed())
            {
            policy = SEC_AUTH_ALLOWED_BY_PASS;
            }
         else
            {
            if(0 == tls_allow_autologin())
               {
               policy = SEC_AUTH_REQUIRE_BOTH;
               }
            }
         break;
#endif /* USE_TLS */
      default:
         policy = SEC_AUTH_REQUIRE_STRONG;
      }
   return(policy);
   }

/*
 * these function will get the policy of the server towards 
 *  CCC.  see secutil.h for descriptions
 */

int get_ccc_policy( void )
   {
   int policy = SEC_CCC_DISALLOWED;
   switch(AuthMechanism)
      {
      case SEC_MECHANISM_NONE:
         policy = SEC_CCC_DISALLOWED;
         break;
#if defined (USE_GSS)
      case SEC_MECHANISM_GSS:
         /*
          * Once the security of the channel is established,
          * it cannot be downgraded.
          */
         if ((gss_info.authstate & GSS_ADAT_DONE) == GSS_ADAT_DONE)
             policy = SEC_CCC_DISALLOWED;
         else
             policy = SEC_CCC_ALLOWED;
         break;
#endif /* USE_GSS */
#if defined (USE_TLS)
      case SEC_MECHANISM_TLS:
         if(1 == tls_is_ccc_allowed())
            {
            policy = SEC_CCC_ALLOWED;
            }
         break;
#endif /* USE_TLS */
      default:
         policy = SEC_CCC_DISALLOWED;
      }
   return(policy);
   }

/*
 * these functions will set and check the data connection policy
 *  against the current state.
 */

static unsigned char CurrentProtLevel = 'C';
static int CurrentProtMechanism = SEC_DATA_MECHANISM_PLAIN;

void set_data_prot_level(unsigned char ProtLevel)
   {
   CurrentProtLevel = toupper(ProtLevel);
   return;
   }

void set_data_prot_mechanism(int SecurityType)
   {
   CurrentProtMechanism = toupper(SecurityType);
   return;
   }

/*
 * NOTE: this function should be called when processing 
 *  STOR, RETR, STOU, NLST, LIST and APPE - not when setting
 *  PROT.
 */
int is_data_connection_secure_enough(const char *parm, int ftpCommand)
   {
   int allow = 0;
   switch(AuthMechanism)
      {
      case SEC_MECHANISM_NONE:
         /*
          * NOTE: in order to force secure data connections, the 
          *  server has to be configured to force secure control 
          *  connections, because this code will not prevent
          *  a plaintext data connection on a control connection 
          *  that has never been protected.
          */
         allow = 1;
         break;
#if defined (USE_GSS)
      case SEC_MECHANISM_GSS:
         allow = 1;
         break;
#endif /* USE_GSS */
#if defined (USE_TLS)
      case SEC_MECHANISM_TLS:
         allow = tls_check_data_prot(parm,ftpCommand);
         break;
#endif /* USE_TLS */
      default:
         allow = 0;
      }
   return(allow);
   }

unsigned char get_data_prot_level( void )
   {
   return(CurrentProtLevel);
   }

int get_data_prot_mechanism( void )
   {
   return(CurrentProtMechanism);
   }

unsigned char *get_data_prot_string( void )
   {
   static unsigned char text[50];
   memset(text,'\0',sizeof(text));
   /*
    * these are the descriptions defined by RFC2228
    *
    * C - 'clear' means no protection
    * E - 'confidential' means confidentiality protected (encrypted)
    * S - 'safe' means integrity protected
    * P - 'private' means integrity and confidentiality protected
    *
    * not all mechanisms support all options.
    */

   switch(CurrentProtLevel)
      {
      case 'C':
         strcpy(text," clear ");
         break;
      case 'E':
         strcpy(text," confidential ");
         break;
      case 'S':
         strcpy(text," safe ");
         break;
      case 'P':
         strcpy(text," private ");
         break;
      default:
         strcpy(text," unknown ");
      }
   return(text);
   }


#endif /* defined(USE_SECURITY) */

