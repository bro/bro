// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

namespace zeek::packet_analysis::UDP {

class UDPAnalyzer : public zeek::packet_analysis::IP::IPBasedAnalyzer {
public:
	UDPAnalyzer();
	~UDPAnalyzer() override;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<UDPAnalyzer>();
		}

protected:

	/**
	 * Returns the port mask for an analyzer. Used by IsLikelyServerPort().
	 */
	uint32_t GetServerPortMask() const override { return UDP_PORT_MASK; }

	/**
	 * Returns the transport protocol. Used by NewConn().
	 */
	TransportProto GetTransportProto() const override { return TRANSPORT_UDP; }

	/**
	 * Upon seeing the first packet of a connection, checks whether we want
	 * to analyze it (e.g. we may not want to look at partial connections)
	 * and, if yes, whether we should flip the roles of originator and
	 * responder based on known ports and such.
	 *
	 * @param src_port The source port of the connection.
	 * @param dst_port The destination port of the connection.
	 * @param data The payload data for the packet being processed.
	 * @param flip_roles Return value if the roles should be flipped.
	 * @return True if the connection is wanted. False otherwise.
	 */
	bool WantConnection(uint16_t src_port, uint16_t dst_port,
	                    const u_char* data, bool& flip_roles) const override;
};

}
