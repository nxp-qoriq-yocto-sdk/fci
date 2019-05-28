/*
*   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
*   Copyright 2016 NXP
*
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*
*/


#ifndef _FCI_H
#define _FCI_H

/*
* Prototypes
*/

/* FPP Forward Engine API*/
extern int comcerto_fpp_send_command(unsigned short fcode, unsigned short length, unsigned short *payload, unsigned short *, unsigned short *);
extern int comcerto_fpp_register_event_cb(void *cb);

/*
* Debug macros
*/

#define FCI_PRINT	0
#define FCI_INIT	1
#define FCI_STAT	1
#define FCI_OUTBOUND	1
#define FCI_INBOUND	1
#define FCI_DUMP	1
#define FCI_NL		1
#define FCI_ACK		1

#ifdef FCI_PRINT
#define FCI_PRINTK(type, info, args...) do {if(type) printk(KERN_DEBUG info, ## args);} while(0);
#else
#define FCI_PRINTK(type, info, args...) do {} while(0);
#endif

/* Supported netlink protocol type NETLINK_FF */
#define FCI_NL_FF		0
#define FCI_MAX_PROTO		1

/* Netlink multicast groups supported by FCI */
#define NL_FF_GROUP	1

/* FCI message definitions*/
#define FCI_MSG_MAX_PAYLOAD	256
#define FCI_MSG_HDR_SIZE 	4 /* fcode + length */
#define FCI_MSG_SIZE		(FCI_MSG_MAX_PAYLOAD + FCI_MSG_HDR_SIZE)

#ifndef NETLINK_FF
#define NETLINK_FF 30
#endif

#ifndef NETLINK_KEY
#define NETLINK_KEY 32
#endif

/*
* Structures
*
*/
typedef struct t_FCI_MSG
{
	/* message data */
	u16 fcode;
	u16 length;
	u16 payload[(FCI_MSG_MAX_PAYLOAD / sizeof(u16))];
} FCI_MSG;


typedef struct t_FCI_SOCK_STATS
{
	unsigned long tx_msg;
	unsigned long rx_msg;
	unsigned long tx_msg_err;
	unsigned long rx_msg_err;
} FCI_SOCK_STATS;


typedef struct t_FCI_STATS
{
	/* Globlas Statistics*/
	unsigned long tx_msg;
	unsigned long rx_msg;
	unsigned long tx_msg_err;
	unsigned long rx_msg_err;
	unsigned long mem_alloc_err;
	unsigned long kernel_create_err;
	unsigned long unknown_sock_type;
	/* Per socket type statistics*/
	FCI_SOCK_STATS sock_stats[FCI_MAX_PROTO];
} FCI_STATS;


typedef struct t_FCI
{
	struct sock *fci_nl_sock[FCI_MAX_PROTO];
	FCI_STATS stats;
} FCI;



#endif /* _FCI_H */
