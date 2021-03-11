// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

#include "zeek/RunState.h"
#include "zeek/Conn.h"
#include "zeek/Val.h"
#include "zeek/Sessions.h"
#include "zeek/analyzer/Manager.h"

using namespace zeek;
using namespace zeek::packet_analysis::IP;

IPBasedAnalyzer::IPBasedAnalyzer(const char* name)
	: zeek::packet_analysis::Analyzer(name)
	{
	}

IPBasedAnalyzer::~IPBasedAnalyzer()
	{
	}

void IPBasedAnalyzer::ProcessConnection(const ConnID& conn_id, const Packet* pkt, size_t remaining)
	{
	const std::unique_ptr<IP_Hdr>& ip_hdr = pkt->ip_hdr;
	detail::ConnIDKey key = detail::BuildConnIDKey(conn_id);

	// TODO: check with the session manager to see whether this connection exists
	Connection* conn = sessions->FindConnection(key, GetTransportProto());

	if ( ! conn )
		{
		conn = NewConn(&conn_id, key, run_state::processing_start_time, pkt);
		if ( conn )
			Insert(conn);
		}
	else
		{
		if ( conn->IsReuse(run_state::processing_start_time, ip_hdr->Payload()) )
			{
			conn->Event(connection_reused, nullptr);

			// TODO: why do we do this Insert/Recreate/Remove dance here? Why can't the
			// existing connection object just be "refreshed" in some way?
			Remove(conn);
			conn = NewConn(&conn_id, key, run_state::processing_start_time, pkt);
			if ( conn )
				Insert(conn);
			}
		else
			{
			conn->CheckEncapsulation(pkt->encap);
			}
		}

	if ( ! conn )
		return;

	bool is_orig = (conn_id.src_addr == conn->OrigAddr()) &&
		(conn_id.src_port == conn->OrigPort());

	conn->CheckFlowLabel(is_orig, ip_hdr->FlowLabel());

	zeek::ValPtr pkt_hdr_val = ip_hdr->ToPktHdrVal();

	if ( ipv6_ext_headers && ip_hdr->NumHeaders() > 1 )
		conn->EnqueueEvent(ipv6_ext_headers, nullptr, conn->GetVal(),
		                   pkt_hdr_val);

	if ( new_packet )
		conn->EnqueueEvent(new_packet, nullptr, conn->GetVal(), std::move(pkt_hdr_val));

	int record_packet = 1;	// whether to record the packet at all
	int record_content = 1;	// whether to record its data

	// TODO: do this here, or pass it down from the child analyzer?
	const u_char* data = pkt->ip_hdr->Payload();

	conn->NextPacket(run_state::processing_start_time, is_orig, ip_hdr.get(), ip_hdr->PayloadLen(),
	                 remaining, data, record_packet, record_content, pkt);

	// TODO: this doesn't feel right here but it doesn't feel right in the IP analyzer
	// either. If we're not handling something IP-based, how does the packet get recorded?

	// We skip this block for reassembled packets because the pointer
	// math wouldn't work.
	if ( ! ip_hdr->reassembled && record_packet )
		{
		if ( record_content )
			pkt->dump_packet = true;	// save the whole thing

		else
			{
			int hdr_len = data - pkt->data;
			packet_mgr->DumpPacket(pkt, hdr_len);	// just save the header
			}
		}
	}

bool IPBasedAnalyzer::CheckHeaderTrunc(size_t min_hdr_len, size_t remaining, Packet* packet)
	{
	if ( packet->ip_hdr->PayloadLen() < min_hdr_len )
		{
		Weird("truncated_header", packet);
		return false;
		}
	else if ( remaining < min_hdr_len )
		{
		Weird("internally_truncated_header", packet);
		return false;
		}

	return true;
	}

bool IPBasedAnalyzer::IsLikelyServerPort(uint32_t port) const
	{
	// We keep a cached in-core version of the table to speed up the lookup.
	static std::set<bro_uint_t> port_cache;
	static bool have_cache = false;

	if ( ! have_cache )
		{
		auto likely_server_ports = id::find_val<TableVal>("likely_server_ports");
		auto lv = likely_server_ports->ToPureListVal();
		for ( int i = 0; i < lv->Length(); i++ )
			port_cache.insert(lv->Idx(i)->InternalUnsigned());
		have_cache = true;
		}

	// We exploit our knowledge of PortVal's internal storage mechanism here.
	port |= GetServerPortMask();

	return port_cache.find(port) != port_cache.end();
	}

// TODO: this probably doesn't need to take a time value here. Just use the run_state.
zeek::Connection* IPBasedAnalyzer::NewConn(const ConnID* id, const detail::ConnIDKey& key,
                                           double t, const Packet* pkt)
	{
	int src_h = ntohs(id->src_port);
	int dst_h = ntohs(id->dst_port);
	bool flip = false;

	if ( ! WantConnection(src_h, dst_h, pkt->ip_hdr->Payload(), flip) )
		return nullptr;

	// TODO: we shouldn't pass down the session manager to Connection anymore, since Connection
	// may not go into that analyzer tree.
	Connection* conn = new Connection(sessions, key, t, id, pkt->ip_hdr->FlowLabel(), pkt);
	conn->SetTransport(GetTransportProto());

	if ( flip )
		conn->FlipRoles();

	if ( ! analyzer_mgr->BuildInitialAnalyzerTree(conn) )
		{
		conn->Done();
		Unref(conn);
		return nullptr;
		}

	if ( new_connection )
		conn->Event(new_connection, nullptr);

	return conn;
	}

void IPBasedAnalyzer::Insert(Connection* c)
	{
	// TODO: temporarily use sessions for this until i can redo all of that code
	sessions->Insert(c, false);

	// TODO: insert connection into session manager
	// TODO: update statistics for child class
	}

void IPBasedAnalyzer::Remove(Connection* c)
	{
	// TODO: temporarily use sessions for this until i can redo all of that code
	sessions->Remove(c);
	}
