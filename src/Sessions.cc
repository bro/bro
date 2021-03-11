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
#include "zeek/Session.h"
#include "zeek/TunnelEncapsulation.h"

#include "zeek/analyzer/protocol/icmp/ICMP.h"
#include "zeek/analyzer/protocol/udp/UDP.h"
#include "zeek/analyzer/Manager.h"

#include "zeek/iosource/IOSource.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/packet_analysis/protocol/ip/IP.h"

namespace zeek {

NetSessions* sessions;

NetSessions::NetSessions()
	{
	packet_filter = nullptr;

	memset(&stats, 0, sizeof(SessionStats));
	}

NetSessions::~NetSessions()
	{
	delete packet_filter;

	Clear();
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
	id.proto = orig_portv->PortType();

	detail::ConnIDKey key = detail::BuildConnIDKey(id);

	Connection* conn = nullptr;
	auto it = sessions.find(key.GetHashKey()->Hash());
	if ( it != sessions.end() )
		conn = static_cast<Connection*>(it->second);

	return conn;
	}

Connection* NetSessions::FindConnection(const detail::ConnIDKey& key, TransportProto proto)
	{
	Connection* conn = nullptr;

	auto it = sessions.find(key.GetHashKey()->Hash());
	if ( it != sessions.end() )
		conn = static_cast<Connection*>(it->second);

	return conn;
	}

void NetSessions::Remove(Session* s)
	{
	if ( s->IsKeyValid() )
		{
		s->CancelTimers();
		s->Done();
		s->RemovalEvent();

		// Clears out the session's copy of the key so that if the
		// session has been Ref()'d somewhere, we know that on a future
		// call to Remove() that it's no longer in the map.
		detail::hash_t hash = s->HashKey()->Hash();
		s->ClearKey();

		if ( sessions.erase(hash) == 0 )
			reporter->InternalWarning("connection missing");

		Unref(s);
		}
	}

void NetSessions::Insert(Session* s, bool remove_existing)
	{
	assert(s->IsKeyValid());

	Session* old = nullptr;
	detail::hash_t hash = s->HashKey()->Hash();

	if ( remove_existing )
		{
		old = Lookup(hash);
		sessions.erase(hash);
		}

	InsertSession(hash, s);

	if ( old && old != s )
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
	for ( const auto& entry : sessions )
		{
		Session* tc = entry.second;
		tc->Done();
		tc->RemovalEvent();
		}
	}

void NetSessions::Clear()
	{
	for ( const auto& entry : sessions )
		Unref(entry.second);

	sessions.clear();

	detail::fragment_mgr->Clear();
	}

void NetSessions::GetStats(SessionStats& s) const
	{
	// TODO: figure this out
	// s.num_TCP_conns = tcp_conns.size();
	// s.cumulative_TCP_conns = stats.cumulative_TCP_conns;
	// s.num_UDP_conns = udp_conns.size();
	// s.cumulative_UDP_conns = stats.cumulative_UDP_conns;
	// s.num_ICMP_conns = icmp_conns.size();
	// s.cumulative_ICMP_conns = stats.cumulative_ICMP_conns;
	s.num_fragments = detail::fragment_mgr->Size();
	s.num_packets = packet_mgr->PacketsProcessed();

	// s.max_TCP_conns = stats.max_TCP_conns;
	// s.max_UDP_conns = stats.max_UDP_conns;
	// s.max_ICMP_conns = stats.max_ICMP_conns;
	s.max_fragments = detail::fragment_mgr->MaxFragments();
	}

Session* NetSessions::Lookup(detail::hash_t hash)
	{
	auto it = sessions.find(hash);
	if ( it != sessions.end() )
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

	for ( const auto& entry : sessions )
		mem += entry.second->MemoryAllocation();

	return mem;
	}

unsigned int NetSessions::ConnectionMemoryUsageConnVals()
	{
	unsigned int mem = 0;

	if ( run_state::terminating )
		// Connections have been flushed already.
		return 0;

	for ( const auto& entry : sessions )
		mem += entry.second->MemoryAllocationConnVal();

	return mem;
	}

unsigned int NetSessions::MemoryAllocation()
	{
	if ( run_state::terminating )
		// Sessions have been flushed already.
		return 0;

	return ConnectionMemoryUsage()
		+ padded_sizeof(*this)
		+ (sessions.size() * sizeof(SessionMap::key_type) + sizeof(SessionMap::value_type))
		+ detail::fragment_mgr->MemoryAllocation();
		// FIXME: MemoryAllocation() not implemented for rest.
		;
	}

void NetSessions::InsertSession(detail::hash_t hash, Session* session)
	{
	sessions[hash] = session;

	// TODO: figure this out.
	/*
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
	*/
	}

} // namespace zeek
