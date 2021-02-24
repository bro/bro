module PacketAnalyzer::IP;

const IPPROTO_TCP : count = 6;
const IPPROTO_UDP : count = 17;
const IPPROTO_ICMP : count = 1;
const IPPROTO_ICMP6 : count = 58;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, 4, PacketAnalyzer::ANALYZER_IPTUNNEL);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, 41, PacketAnalyzer::ANALYZER_IPTUNNEL);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, 47, PacketAnalyzer::ANALYZER_GRE);

	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, IPPROTO_TCP, PacketAnalyzer::ANALYZER_TCP_PKT);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, IPPROTO_UDP, PacketAnalyzer::ANALYZER_UDP_PKT);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, IPPROTO_ICMP, PacketAnalyzer::ANALYZER_ICMP_PKT);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, IPPROTO_ICMP6, PacketAnalyzer::ANALYZER_ICMP_PKT);
	}
