// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "zeek/Sessions.h"

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <unistd.h>

#include <pcap.h>

#include "zeek/Desc.h"
#include "zeek/RunState.h"
#include "zeek/Event.h"
#include "zeek/Timer.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/RuleMatcher.h"
#include "zeek/TunnelEncapsulation.h"

#include "zeek/analyzer/protocol/icmp/ICMP.h"
#include "zeek/analyzer/protocol/udp/UDP.h"
#include "zeek/analyzer/protocol/stepping-stone/SteppingStone.h"
#include "zeek/analyzer/Manager.h"

#include "zeek/iosource/IOSource.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/packet_analysis/protocol/ip/IP.h"

#include "zeek/analyzer/protocol/stepping-stone/events.bif.h"

// These represent NetBIOS services on ephemeral ports.  They're numbered
// so that we can use a single int to hold either an actual TCP/UDP server
// port or one of these.
enum NetBIOS_Service {
	NETBIOS_SERVICE_START = 0x10000L,	// larger than any port
	NETBIOS_SERVICE_DCE_RPC,
};

zeek::NetSessions* zeek::sessions;
zeek::NetSessions*& sessions = zeek::sessions;

namespace zeek {

NetSessions::NetSessions()
	{
	if ( stp_correlate_pair )
		stp_manager = new analyzer::stepping_stone::SteppingStoneManager();
	else
		stp_manager = nullptr;

	packet_filter = nullptr;

	memset(&stats, 0, sizeof(SessionStats));
	}

NetSessions::~NetSessions()
	{
	delete packet_filter;
	delete stp_manager;

	for ( const auto& entry : tcp_conns )
		Unref(entry.second);
	for ( const auto& entry : udp_conns )
		Unref(entry.second);
	for ( const auto& entry : icmp_conns )
		Unref(entry.second);

	detail::fragment_mgr->Clear();
	}

void NetSessions::Done()
	{
	}

int NetSessions::ParseIPPacket(int caplen, const u_char* const pkt, int proto,
                               IP_Hdr*& inner)
	{
	return packet_analysis::IP::IPAnalyzer::ParseIPPacket(caplen, pkt, proto, inner);
	}

Connection* NetSessions::FindConnection(Val* v)
	{
	const auto& vt = v->GetType();
	if ( ! IsRecord(vt->Tag()) )
		return nullptr;

	RecordType* vr = vt->AsRecordType();
	auto vl = v->As<RecordVal*>();

	int orig_h, orig_p;	// indices into record's value list
	int resp_h, resp_p;

	if ( vr == id::conn_id )
		{
		orig_h = 0;
		orig_p = 1;
		resp_h = 2;
		resp_p = 3;
		}

	else
		{
		// While it's not a conn_id, it may have equivalent fields.
		orig_h = vr->FieldOffset("orig_h");
		resp_h = vr->FieldOffset("resp_h");
		orig_p = vr->FieldOffset("orig_p");
		resp_p = vr->FieldOffset("resp_p");

		if ( orig_h < 0 || resp_h < 0 || orig_p < 0 || resp_p < 0 )
			return nullptr;

		// ### we ought to check that the fields have the right
		// types, too.
		}

	const IPAddr& orig_addr = vl->GetFieldAs<AddrVal>(orig_h);
	const IPAddr& resp_addr = vl->GetFieldAs<AddrVal>(resp_h);

	const PortVal* orig_portv = vl->GetFieldAs<PortVal>(orig_p);
	const PortVal* resp_portv = vl->GetFieldAs<PortVal>(resp_p);

	ConnID id;

	id.src_addr = orig_addr;
	id.dst_addr = resp_addr;

	id.src_port = htons((unsigned short) orig_portv->Port());
	id.dst_port = htons((unsigned short) resp_portv->Port());

	id.is_one_way = false;	// ### incorrect for ICMP connections

	detail::ConnIDKey key = detail::BuildConnIDKey(id);
	ConnectionMap* d;

	if ( orig_portv->IsTCP() )
		d = &tcp_conns;
	else if ( orig_portv->IsUDP() )
		d = &udp_conns;
	else if ( orig_portv->IsICMP() )
		d = &icmp_conns;
	else
		{
		// This can happen due to pseudo-connections we
		// construct, for example for packet headers embedded
		// in ICMPs.
		return nullptr;
		}

	Connection* conn = nullptr;
	auto it = d->find(key);
	if ( it != d->end() )
		conn = it->second;

	return conn;
	}

Connection* NetSessions::FindConnection(const detail::ConnIDKey& key, TransportProto proto)
	{
	Connection* conn = nullptr;

	switch ( proto )
		{
		case TRANSPORT_TCP:
			{
			auto it = tcp_conns.find(key);
			if ( it != tcp_conns.end() )
				conn = it->second;
			break;
			}
		case TRANSPORT_UDP:
			{
			auto it = udp_conns.find(key);
			if ( it != udp_conns.end() )
				conn = it->second;
			break;
			}
		case TRANSPORT_ICMP:
			{
			auto it = icmp_conns.find(key);
			if ( it != icmp_conns.end() )
				conn = it->second;
			break;
			}
		default:
			break;
		}

	return conn;
	}

void NetSessions::Remove(Connection* c)
	{
	if ( c->IsKeyValid() )
		{
		const detail::ConnIDKey& key = c->Key();
		c->CancelTimers();

		if ( c->ConnTransport() == TRANSPORT_TCP )
			{
			auto ta = static_cast<analyzer::tcp::TCP_Analyzer*>(c->GetRootAnalyzer());
			assert(ta->IsAnalyzer("TCP"));
			analyzer::tcp::TCP_Endpoint* to = ta->Orig();
			analyzer::tcp::TCP_Endpoint* tr = ta->Resp();

			tcp_stats.StateLeft(to->state, tr->state);
			}

		c->Done();
		c->RemovalEvent();

		// Zero out c's copy of the key, so that if c has been Ref()'d
		// up, we know on a future call to Remove() that it's no
		// longer in the dictionary.
		c->ClearKey();

		switch ( c->ConnTransport() ) {
		case TRANSPORT_TCP:
			if ( tcp_conns.erase(key) == 0 )
				reporter->InternalWarning("connection missing");
			break;

		case TRANSPORT_UDP:
			if ( udp_conns.erase(key) == 0 )
				reporter->InternalWarning("connection missing");
			break;

		case TRANSPORT_ICMP:
			if ( icmp_conns.erase(key) == 0 )
				reporter->InternalWarning("connection missing");
			break;

		case TRANSPORT_UNKNOWN:
			reporter->InternalWarning("unknown transport when removing connection");
			break;
		}

		Unref(c);
		}
	}

void NetSessions::Insert(Connection* c, bool remove_existing)
	{
	assert(c->IsKeyValid());

	Connection* old = nullptr;

	switch ( c->ConnTransport() ) {
	// Remove first. Otherwise the map would still reference the old key for
	// already existing connections.

	case TRANSPORT_TCP:
		if ( remove_existing )
			{
			old = LookupConn(tcp_conns, c->Key());
			tcp_conns.erase(c->Key());
			}
		InsertConnection(&tcp_conns, c->Key(), c);
		break;

	case TRANSPORT_UDP:
		if ( remove_existing )
			{
			old = LookupConn(udp_conns, c->Key());
			udp_conns.erase(c->Key());
			}
		InsertConnection(&udp_conns, c->Key(), c);
		break;

	case TRANSPORT_ICMP:
		if ( remove_existing )
			{
			old = LookupConn(icmp_conns, c->Key());
			icmp_conns.erase(c->Key());
			}
		InsertConnection(&icmp_conns, c->Key(), c);
		break;

	default:
		reporter->InternalWarning("unknown connection type");
		Unref(c);
		return;
	}

	if ( old && old != c )
		{
		// Some clean-ups similar to those in Remove() (but invisible
		// to the script layer).
		old->CancelTimers();
		old->ClearKey();
		Unref(old);
		}
	}

void NetSessions::Drain()
	{
	for ( const auto& entry : tcp_conns )
		{
		Connection* tc = entry.second;
		tc->Done();
		tc->RemovalEvent();
		}

	for ( const auto& entry : udp_conns )
		{
		Connection* uc = entry.second;
		uc->Done();
		uc->RemovalEvent();
		}

	for ( const auto& entry : icmp_conns )
		{
		Connection* ic = entry.second;
		ic->Done();
		ic->RemovalEvent();
		}
	}

void NetSessions::Clear()
	{
	for ( const auto& entry : tcp_conns )
		Unref(entry.second);
	for ( const auto& entry : udp_conns )
		Unref(entry.second);
	for ( const auto& entry : icmp_conns )
		Unref(entry.second);

	tcp_conns.clear();
	udp_conns.clear();
	icmp_conns.clear();

	detail::fragment_mgr->Clear();
	}

void NetSessions::GetStats(SessionStats& s) const
	{
	s.num_TCP_conns = tcp_conns.size();
	s.cumulative_TCP_conns = stats.cumulative_TCP_conns;
	s.num_UDP_conns = udp_conns.size();
	s.cumulative_UDP_conns = stats.cumulative_UDP_conns;
	s.num_ICMP_conns = icmp_conns.size();
	s.cumulative_ICMP_conns = stats.cumulative_ICMP_conns;
	s.num_fragments = detail::fragment_mgr->Size();
	s.num_packets = packet_mgr->PacketsProcessed();

	s.max_TCP_conns = stats.max_TCP_conns;
	s.max_UDP_conns = stats.max_UDP_conns;
	s.max_ICMP_conns = stats.max_ICMP_conns;
	s.max_fragments = detail::fragment_mgr->MaxFragments();
	}

Connection* NetSessions::LookupConn(const ConnectionMap& conns, const detail::ConnIDKey& key)
	{
	auto it = conns.find(key);
	if ( it != conns.end() )
		return it->second;

	return nullptr;
	}

void NetSessions::Weird(const char* name, const Packet* pkt, const char* addl, const char* source)
	{
	const char* weird_name = name;

	if ( pkt )
		{
		pkt->dump_packet = true;

		if ( pkt->encap && pkt->encap->LastType() != BifEnum::Tunnel::NONE )
			weird_name = util::fmt("%s_in_tunnel", name);

		if ( pkt->ip_hdr )
			{
			reporter->Weird(pkt->ip_hdr->SrcAddr(), pkt->ip_hdr->DstAddr(), weird_name, addl, source);
			return;
			}
		}

	reporter->Weird(weird_name, addl, source);
	}

void NetSessions::Weird(const char* name, const IP_Hdr* ip, const char* addl)
	{
	reporter->Weird(ip->SrcAddr(), ip->DstAddr(), name, addl);
	}

unsigned int NetSessions::ConnectionMemoryUsage()
	{
	unsigned int mem = 0;

	if ( run_state::terminating )
		// Connections have been flushed already.
		return 0;

	for ( const auto& entry : tcp_conns )
		mem += entry.second->MemoryAllocation();

	for ( const auto& entry : udp_conns )
		mem += entry.second->MemoryAllocation();

	for ( const auto& entry : icmp_conns )
		mem += entry.second->MemoryAllocation();

	return mem;
	}

unsigned int NetSessions::ConnectionMemoryUsageConnVals()
	{
	unsigned int mem = 0;

	if ( run_state::terminating )
		// Connections have been flushed already.
		return 0;

	for ( const auto& entry : tcp_conns )
		mem += entry.second->MemoryAllocationConnVal();

	for ( const auto& entry : udp_conns )
		mem += entry.second->MemoryAllocationConnVal();

	for ( const auto& entry : icmp_conns )
		mem += entry.second->MemoryAllocationConnVal();

	return mem;
	}

unsigned int NetSessions::MemoryAllocation()
	{
	if ( run_state::terminating )
		// Connections have been flushed already.
		return 0;

	return ConnectionMemoryUsage()
		+ padded_sizeof(*this)
		+ (tcp_conns.size() * (sizeof(ConnectionMap::key_type) + sizeof(ConnectionMap::value_type)))
		+ (udp_conns.size() * (sizeof(ConnectionMap::key_type) + sizeof(ConnectionMap::value_type)))
		+ (icmp_conns.size() * (sizeof(ConnectionMap::key_type) + sizeof(ConnectionMap::value_type)))
		+ detail::fragment_mgr->MemoryAllocation();
		// FIXME: MemoryAllocation() not implemented for rest.
		;
	}

void NetSessions::InsertConnection(ConnectionMap* m, const detail::ConnIDKey& key, Connection* conn)
	{
	(*m)[key] = conn;

	switch ( conn->ConnTransport() )
		{
		case TRANSPORT_TCP:
			stats.cumulative_TCP_conns++;
			if ( m->size() > stats.max_TCP_conns )
				stats.max_TCP_conns = m->size();
			break;
		case TRANSPORT_UDP:
			stats.cumulative_UDP_conns++;
			if ( m->size() > stats.max_UDP_conns )
				stats.max_UDP_conns = m->size();
			break;
		case TRANSPORT_ICMP:
			stats.cumulative_ICMP_conns++;
			if ( m->size() > stats.max_ICMP_conns )
				stats.max_ICMP_conns = m->size();
			break;
		default: break;
		}
	}

} // namespace zeek
