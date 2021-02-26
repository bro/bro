// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

namespace zeek::packet_analysis::ICMP {

class ICMPAnalyzer : public zeek::packet_analysis::IP::IPBasedAnalyzer {
public:
	ICMPAnalyzer();
	~ICMPAnalyzer() override;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<ICMPAnalyzer>();
		}

protected:

	/**
	 * Returns the port mask for an analyzer used by IsLikelyServerPort.
	 */
	uint32_t GetServerPortMask() const override { return ICMP_PORT_MASK; }

	/**
	 * Returns the transport protocol. Used by NewConn().
	 */
	TransportProto GetTransportProto() const override { return TRANSPORT_ICMP; }
};

}
