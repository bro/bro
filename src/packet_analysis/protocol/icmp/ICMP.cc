// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/icmp/ICMP.h"
#include "zeek/RunState.h"
#include "zeek/session/SessionManager.h"
#include "zeek/Conn.h"
#include "zeek/analyzer/protocol/icmp/ICMP.h"

using namespace zeek::packet_analysis::ICMP;

ICMPAnalyzer::ICMPAnalyzer()
	: zeek::packet_analysis::IP::IPBasedAnalyzer("ICMP_PKT")
	{
	}

ICMPAnalyzer::~ICMPAnalyzer()
	{
	}

bool ICMPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( ! CheckHeaderTrunc(ICMP_MINLEN, len, packet) )
		return false;

	ConnID id;
	id.src_addr = packet->ip_hdr->SrcAddr();
	id.dst_addr = packet->ip_hdr->DstAddr();
	id.proto = TRANSPORT_ICMP;

	if ( packet->proto == IPPROTO_ICMP )
		{
		const struct icmp* icmpp = (const struct icmp *) data;
		id.src_port = icmpp->icmp_type;
		id.dst_port = analyzer::icmp::ICMP4_counterpart(icmpp->icmp_type,
		                                                icmpp->icmp_code,
		                                                id.is_one_way);

		id.src_port = htons(id.src_port);
		id.dst_port = htons(id.dst_port);
		}
	else if ( packet->proto == IPPROTO_ICMPV6 )
		{
		const struct icmp* icmpp = (const struct icmp *) data;
		id.src_port = icmpp->icmp_type;
		id.dst_port = analyzer::icmp::ICMP6_counterpart(icmpp->icmp_type,
		                                                icmpp->icmp_code,
		                                                id.is_one_way);
		id.src_port = htons(id.src_port);
		id.dst_port = htons(id.dst_port);
		}
	else
		{
		// TODO: how'd we get here?
		}

	ProcessConnection(id, packet, len);

	return true;
	}
