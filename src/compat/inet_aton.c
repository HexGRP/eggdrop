/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * inet_aton.c -- provides inet_aton() if necessary.
 *
 * Portions Copyright (C) 2000 - 2024 Eggheads Development Team
 */

#include "main.h"
#include "inet_aton.h"

#ifndef HAVE_ISASCII
#  define inet_isascii(x) 1 /* Let checks succeed if we don't have isascii(). */
#else
#  define inet_isascii(x) egg_isascii(x)
#endif

#ifndef HAVE_INET_ATON
/*-
 * SPDX-License-Identifier: (BSD-3-Clause AND ISC)
 *
 * Copyright (c) 1983, 1990, 1993
 *    The Regents of the University of California.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Portions Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static const char sccsid[] = "@(#)inet_addr.c  8.1 (Berkeley) 6/17/93";
static const char rcsid[] = "$Id: inet_addr.c,v 1.5 2005/04/27 04:56:19 sra Exp $";
#endif /* LIBC_SCCS and not lint */

#include <sys/param.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>

/*
 * Check whether "cp" is a valid ascii representation
 * of an Internet address and convert to a binary address.
 * Returns 1 if the address is valid, 0 if not.
 * This replaces inet_addr, the return value from which
 * cannot distinguish between failure and a local broadcast address.
 */
int egg_inet_aton(const char *cp, struct in_addr *addr) {
  u_long val;
  int base, n;
  char c;
  uint8_t parts[4];
  uint8_t *pp = parts;
  int digit;

  c = *cp;
  for (;;) {
    /*
     * Collect number up to ``.''.
     * Values are specified as for C:
     * 0x=hex, 0=octal, isdigit=decimal.
     */
    if (!isdigit((unsigned char)c))
      return (0);
    val = 0; base = 10; digit = 0;
    if (c == '0') {
      c = *++cp;
      if (c == 'x' || c == 'X')
        base = 16, c = *++cp;
      else {
        base = 8;
        digit = 1 ;
      }
    }
    for (;;) {
      if (isascii(c) && isdigit((unsigned char)c)) {
        if (base == 8 && (c == '8' || c == '9'))
          return (0);
        val = (val * base) + (c - '0');
        c = *++cp;
        digit = 1;
      } else if (base == 16 && isascii(c) && 
           isxdigit((unsigned char)c)) {
        val = (val << 4) |
          (c + 10 - (islower((unsigned char)c) ? 'a' : 'A'));
        c = *++cp;
        digit = 1;
      } else
        break;
    }
    if (c == '.') {
      /*
       * Internet format:
       *  a.b.c.d
       *  a.b.c  (with c treated as 16 bits)
       *  a.b  (with b treated as 24 bits)
       */
      if (pp >= parts + 3 || val > 0xffU)
        return (0);
      *pp++ = val;
      c = *++cp;
    } else
      break;
  }
  /*
   * Check for trailing characters.
   */
  if (c != '\0' && (!isascii(c) || !isspace((unsigned char)c)))
    return (0);
  /*
   * Did we get a valid digit?
   */
  if (!digit)
    return (0);
  /*
   * Concoct the address according to
   * the number of parts specified.
   */
  n = pp - parts + 1;
  switch (n) {
  case 1:        /* a -- 32 bits */
    break;

  case 2:        /* a.b -- 8.24 bits */
    if (val > 0xffffffU)
      return (0);
    val |= (uint32_t)parts[0] << 24;
    break;

  case 3:        /* a.b.c -- 8.8.16 bits */
    if (val > 0xffffU)
      return (0);
    val |= ((uint32_t)parts[0] << 24) | (parts[1] << 16);
    break;

  case 4:        /* a.b.c.d -- 8.8.8.8 bits */
    if (val > 0xffU)
      return (0);
    val |= ((uint32_t)parts[0] << 24) | (parts[1] << 16) |
        (parts[2] << 8);
    break;
  }
  if (addr != NULL)
    addr->s_addr = htonl(val);
  return (1);
}
#endif /* !HAVE_INET_ATON */
