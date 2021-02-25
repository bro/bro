// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/icmp/ICMP.h"
#include "zeek/RunState.h"
#include "zeek/Sessions.h"

using namespace zeek::packet_analysis::ICMP;

ICMPAnalyzer::ICMPAnalyzer()
	: zeek::packet_analysis::Analyzer("ICMP_PKT")
	{
	}

ICMPAnalyzer::~ICMPAnalyzer()
	{
	}

bool ICMPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	uint32_t post_ip_len = packet->ip_hdr->TotalLen() - packet->ip_hdr->HdrLen();

	if ( post_ip_len < ICMP_MINLEN )
		{
		Weird("truncated_header", packet);
		return false;
		}
	else if ( len < ICMP_MINLEN )
		{
		Weird("internally_truncated_header", packet);
		return false;
		}

	sessions->ProcessTransportLayer(run_state::processing_start_time, packet, len);
	return true;
	}
