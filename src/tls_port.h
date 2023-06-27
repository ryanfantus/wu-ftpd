/*
 * Copyright (c) 2001 IBM (paulfordh@uk.ibm.com)
 * All rights reserved.
 *
 * Use and distribution of this software and its source code are governed
 * by the terms and conditions of the WU-FTPD Software License ("LICENSE").
 *
 * If you did not receive a copy of the license, it may be obtained online
 * at http://www.wu-ftpd.info/license.html.
 */


#if !defined(HEADER_TLS_PORT_H)
#  define HEADER_TLS_PORT_H

#  if defined(USE_TLS)

/*
 * include the header from Pete Runestigs tls utils
 */
#    include "tlsutil.h"

#    define READ    tls_read
#    define WRITE   tls_write
#    define GETC    tls_fgetc
#    define PUTC    tls_fputc
#    define FFLUSH  tls_fflush
#    define CLOSE   tls_close
#    define FCLOSE  tls_fclose
#    define PRINTF  tls_printf
#    define FPRINTF tls_fprintf
#    define VPRINTF tls_vprintf
#    define VFPRINTF tls_vfprintf
#    define FPUTS   tls_fputs

#  else /* !(defined(USE_TLS)) */ 

#    define READ    read
#    define WRITE   write
#    define GETC    getc
#    define FFLUSH  fflush
#    define PUTC    putc
#    define CLOSE   close
#    define FCLOSE  fclose
#    define PRINTF  printf
#    define FPRINTF fprintf
#    define VPRINTF vprintf
#    define VFPRINTF vfprintf
#    define FPUTS   fputs

#  endif /* !(defined(USE_TLS)) */ 

#endif /* !defined(HEADER_TLS_PORT_H) */ 
