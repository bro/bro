// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/tcp/TCP.h"
#include "zeek/RunState.h"
#include "zeek/Sessions.h"

using namespace zeek::packet_analysis::TCP;

TCPAnalyzer::TCPAnalyzer()
	: zeek::packet_analysis::Analyzer("TCP_PKT")
	{
	}

TCPAnalyzer::~TCPAnalyzer()
	{
	}

bool TCPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	uint32_t post_ip_len = packet->ip_hdr->TotalLen() - packet->ip_hdr->HdrLen();
	uint32_t min_hdr_len = sizeof(struct tcphdr);

	if ( post_ip_len < min_hdr_len )
		{
		Weird("truncated_header", packet);
		return false;
		}
	else if ( len < min_hdr_len )
		{
		Weird("internally_truncated_header", packet);
		return false;
		}

	sessions->ProcessTransportLayer(run_state::processing_start_time, packet, len);
	return true;
	}
