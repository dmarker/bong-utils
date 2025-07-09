/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <netgraph.h>
#include <netgraph/ng_pcap.h>

#include "ngpcap.h"


ng_ID_t	
ngp_create(ngctx ctrl, const char *peer, const char *peerhook)
{
	int rc;
	struct ng_mesg *resp;
	struct ngm_mkpeer msg = {
		.type = NG_PCAP_NODE_TYPE,
		.peerhook = NG_PCAP_HOOK_SNOOP,
	};
	char pth[NG_PATHSIZE];
	ng_ID_t nd;

	assert(ctrl >= 0);
	assert(peer != NULL);		assert(strlen(peer) < NG_NODESIZ);
	assert(peerhook != NULL);	assert(strlen(peerhook) < NG_HOOKSIZ);

	strcpy(pth, peer);
	strcat(pth, ":");
	strcat(pth, peerhook);

	strcpy(msg.ourhook, peerhook);

	rc = NgSendMsg(
		ctrl, peer, NGM_GENERIC_COOKIE, NGM_MKPEER, &msg, sizeof(msg)
	);
	if (rc == -1) err(
		ERREXIT, "unable to create %s", msg.type
	);

	rc = NgSendMsg(ctrl, pth, NGM_GENERIC_COOKIE, NGM_NODEINFO, NULL, 0);
	if (rc == -1) errx(
		ERREXIT, "unable to request %s info, presumed dead", msg.type
	);

	rc = NgAllocRecvMsg(ctrl, &resp, NULL);
	if (rc == -1) err(
		ERREXIT, "unable to retrieve %s info, presumed dead", msg.type
	);
		
	/*
	 * This warns about structure alignment but is also done in ngctl(8).
	 */
	nd = ((struct nodeinfo *) resp->data)->id;
	free(resp);
	
	return (nd);
}

void
ngp_set_snaplen(ngctx ctrl, ng_ID_t pcap, int32_t snaplen)
{
	int rc;
	char pth[NG_NODESIZ + 1]; /* extra for ':' */
	struct ng_pcap_config msg = { .snaplen = snaplen };
	
	snprintf(pth, sizeof(pth), IDFMT, pcap);

	rc = NgSendMsg(ctrl, pth, NGM_PCAP_COOKIE, NGM_PCAP_SET_CONFIG, &msg,
	    sizeof(msg));
	if (rc == -1) errx(
		ERREXIT, "%s unable to set snaplen=%d", pth, snaplen
	);
}

void
ngp_connect(
	ngctx ctrl, ng_ID_t pcap,
	uint8_t snum,
	const char *peer, const char *peerhook
) {
	int rc;
	char pth[NG_NODESIZ + 1]; /* extra for ':' */
	struct ngm_connect msg;

	assert(snum < NG_PCAP_PKT_TYPE_LENGTH);
	assert(ctrl >= 0);		assert(pcap > 0);
	assert(peer != NULL);		assert(strlen(peer) < NG_NODESIZ);
	assert(peerhook !=NULL);	assert(strlen(peerhook) < NG_HOOKSIZ);

	snprintf(pth, sizeof(pth), IDFMT, pcap);
	snprintf(msg.ourhook, sizeof(msg.ourhook), "%s%u", NG_PCAP_HOOK_SOURCE, snum);

	snprintf(msg.path, sizeof(msg.path), "%s:", peer);
	strncpy(msg.peerhook, peerhook, sizeof(msg.peerhook));

	rc = NgSendMsg(ctrl, pth, NGM_GENERIC_COOKIE, NGM_CONNECT, &msg,
	    sizeof(msg));
	if (rc == -1) err(
		EX_DATAERR,
		"unable to connect `%s%s' to `%s%s'",
		pth, msg.ourhook, msg.path, msg.peerhook
	);
}

void
ngp_set_type(ngctx ctrl, ng_ID_t pcap, uint8_t snum, enum pkt_type pkt)
{
	int rc;
	char pth[NG_NODESIZ + 1]; /* extra for ':' */
	struct ng_pcap_set_source_type msg;

	/* this has to follow the same order as enum pkt_type in ngpcap.h */
	char *hook_pkt[] = {
		HOOK_PKT_ETHER,
#		ifdef INET
		HOOK_PKT_INET4,
#		endif
#		ifdef INET6
		HOOK_PKT_INET6
#		endif
	};

	snprintf(
		msg.hook_name, sizeof(msg.hook_name),
		"%s%u", NG_PCAP_HOOK_SOURCE, snum
	);
	strcpy(msg.packet_type, hook_pkt[pkt]);

	rc = NgSendMsg(
		ctrl, pth,
		NGM_PCAP_COOKIE, NGM_PCAP_SET_SOURCE_TYPE,
		&msg, sizeof(msg)
	);
	if (rc == -1) err(
		EX_DATAERR,
		"unable to set `%s%s' to `%s'",
		pth, msg.hook_name, msg.packet_type
	);
}
