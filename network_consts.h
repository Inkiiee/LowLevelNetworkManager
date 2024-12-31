#ifndef NETWORK_CONSTS_H
#define NETWORK_CONSTS_H

#include <QObject>

const quint16 proto_ipv4 = 0x0800;
const quint16 proto_arp = 0x0806;
const quint16 proto_frame_relay_arp = 0x0808;
const quint16 proto_pptp = 0x880B;
const quint16 proto_gsmp = 0x880C;
const quint16 proto_rarp = 0x8035;
const quint16 proto_ipv6 = 0x86DD;
const quint16 proto_mpls = 0x8847;
const quint16 proto_mpls_width_upstream = 0x8848;
const quint16 proto_mcap = 0x8861;
const quint16 proto_ppp_over_ethernet_discovery_stage = 0x8863;
const quint16 proto_ppp_over_ethernet_session_stage = 0x8864;
const quint16 proto_customer_vlan = 0x8100;
const quint16 proto_ethernet_passive_optical_network = 0x8808;
const quint16 proto_port_based_network_access_control = 0x888E;
const quint16 proto_service_vlan = 0x88A8;
const quint16 proto_local_experimental_ethertype = 0x88B5;
const quint16 proto_local_experimental_ethertype2 = 0x88B6;
const quint16 proto_oui_extended_ethertype = 0x88B7;
const quint16 proto_pre_authentication = 0x88C7;
const quint16 proto_lldp = 0x88CC;
const quint16 proto_media_access_control_security = 0x88E5;
const quint16 proto_mvrp = 0x88F5;
const quint16 proto_mmrp = 0x88F6;
const quint16 proto_fast_roaming_remote_request = 0x890D;

const quint16 arp_reserverd = 0;
const quint16 arp_request = 1;
const quint16 arp_reply = 2;
const quint16 arp_request_reverse = 3;
const quint16 arp_reply_reverse = 4;
const quint16 arp_drarp_request = 5;
const quint16 arp_drarp_reply = 6;
const quint16 arp_drarp_error = 7;
const quint16 arp_inarp_request = 8;
const quint16 arp_inarp_reply = 9;
const quint16 arp_arp_nak = 10;
const quint16 arp_mars_request = 11;
const quint16 arp_mars_multi = 12;
const quint16 arp_mars_mserv = 13;
const quint16 arp_mars_join = 14;
const quint16 arp_mars_leave = 15;
const quint16 arp_mars_nak = 16;
const quint16 arp_mars_unserv = 17;
const quint16 arp_mars_sjoin = 18;
const quint16 arp_mars_sleave = 19;
const quint16 arp_mars_grouplist_request = 20;
const quint16 arp_mars_grouplist_reply = 21;
const quint16 arp_mars_redirect_map = 22;
const quint16 arp_mapos_unarp = 23;
const quint16 arp_op_exp1 = 24;
const quint16 arp_op_exp2 = 25;

const quint8 icmp_type_echo_reply = 0;
const quint8 icmp_type_destination_unreachable = 3;
const quint8 icmp_type_redirect = 5;
const quint8 icmp_type_echo_request = 8;
const quint8 icmp_type_time_exceeded = 11;
const quint8 icmp_type_parameter_problem = 12;
const quint8 icmp_type_timestamp_request = 13;
const quint8 icmp_type_timestamp_reply = 14;

const quint8 ip_can_not_fragment = 0x40;
const quint8 ip_more_fragment = 0x20;

const quint16 dns_query = 0x0000;
const quint16 dns_reply = 0x8000;
const quint16 dns_op_std_query = 0x0000;
const quint16 dns_op_reverse_search = 0x0800;
const quint16 dns_op_state_server = 0x1000;
const quint16 dns_aa = 0x0400;
const quint16 dns_not_aa = 0x0000;
const quint16 dns_tc = 0x0200;
const quint16 dns_not_tc = 0x0000;
const quint16 dns_rd = 0x0100;
const quint16 dns_not_rd = 0x0000;

const quint16 dns_ra = 0x0080;
const quint16 dns_not_ra = 0x0000;
const quint16 dns_recode_normal = 0x0000;
const quint16 dns_recode_error_format = 0x0001;
const quint16 dns_recode_failed_server = 0x0002;
const quint16 dns_recode_error_name = 0x0003;
const quint16 dns_recode_not_support = 0x0004;
const quint16 dns_recode_refused = 0x0005;

const quint16 dns_type_a = 0x0001;
const quint16 dns_type_ns = 0x0002;
const quint16 dns_type_cname = 0x0005;
const quint16 dns_type_soa = 0x0006;
const quint16 dns_type_ptr = 0x000c;
const quint16 dns_type_mx = 0x000f;
const quint16 dns_type_txt = 0x0010;
const quint16 dns_type_aaaa = 0x001c;
const quint16 dns_type_srv = 0x0021;
const quint16 dns_type_any = 0x00ff;

const quint16 dns_class_in = 0x0001;
const quint16 dns_class_ch = 0x0003;
const quint16 dns_class_hs = 0x0004;
const quint16 dns_class_any = 0x00ff;

#endif // NETWORK_CONSTS_H
