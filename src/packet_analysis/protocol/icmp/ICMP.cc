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
	sessions->ProcessTransportLayer(run_state::processing_start_time, packet, len);
	return true;
	}
