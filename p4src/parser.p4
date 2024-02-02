// Ingress and egress parser/deparser definition
#include "../config.h"

#ifndef _PARSER_
#define _PARSER_

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        ig_md.bitmap = 0;
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }
    state parse_resubmit {
        // Parse resubmitted packet here.
        pkt.advance(64);
        transition parse_ethernet;
    }
    state parse_port_metadata {
        pkt.advance(64);  //tofino 1 port metadata size
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        ig_md.bitmap = ig_md.bitmap | ETHERNET_BITMAP;
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_TUNNEL : parse_tunnel;
            default : accept;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan);
        transition select (hdr.vlan.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default: accept;
        }
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        ig_md.bitmap = ig_md.bitmap | IPV4_BITMAP;
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_tunnel {
        pkt.extract(hdr.tunnel);
        ig_md.bitmap = ig_md.bitmap | TUNNEL_BITMAP;
        transition accept;
    }

    state parse_tcp {
        ig_md.bitmap = ig_md.bitmap | TCP_BITMAP;
        pkt.extract(hdr.l4_port);
        pkt.extract(hdr.tcp);
        transition parse_recirculation;
    }

    state parse_udp {
        pkt.extract(hdr.l4_port);
        pkt.extract(hdr.udp);
        ig_md.bitmap = ig_md.bitmap | UDP_BITMAP;
        transition select(hdr.l4_port.dst_port) {
            UDP_PORT_NETCACHE : parse_netcache;
            UDP_PORT_CACULATION: parse_cacl;
            UDP_PORT_DQACC: parse_dq;
            default: parse_recirculation;
        }
    }

    state parse_netcache {
        pkt.extract(hdr.l5);
        ig_md.bitmap = ig_md.bitmap | NETCACHE_BITMAP;
        transition parse_recirculation;
    }
    state parse_cacl {
        ig_md.bitmap = ig_md.bitmap | CACULATION_BITMAP;
        pkt.extract(hdr.l5);
        transition parse_recirculation;
    }
    state parse_dq {
        ig_md.bitmap = ig_md.bitmap | DQACC_BITMAP;
        pkt.extract(hdr.l5);
        transition parse_recirculation;
    }

    state parse_recirculation {
        transition select (ig_intr_md.ingress_port) {
            PORT_RECIRCULATION : parse_meta;
            default : parse_newmeta;
        }
    }

    state parse_meta {
        pkt.extract(hdr.meta);
        transition accept;
    }

    state parse_newmeta {
        hdr.meta.setValid();
        transition accept;
    }

}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tunnel);
        pkt.emit(hdr.l4_port);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.l5);
        pkt.emit(hdr.meta);
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
        
    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_TUNNEL : parse_tunnel;
            default : accept;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan);
        transition select (hdr.vlan.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_tunnel {
        pkt.extract(hdr.tunnel);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.l4_port);
        pkt.extract(hdr.tcp);
        transition parse_meta;
    }

    state parse_udp {
        pkt.extract(hdr.l4_port);
        pkt.extract(hdr.udp);
        transition select(hdr.l4_port.dst_port) {
            UDP_PORT_NETCACHE : parse_netcache;
            UDP_PORT_CACULATION: parse_cacl;
            UDP_PORT_DQACC: parse_dq;
            default: parse_meta;
        }
    }

    state parse_netcache {
        pkt.extract(hdr.l5);
        transition parse_meta;
    }
    
    state parse_cacl {
        pkt.extract(hdr.l5);
        transition parse_meta;
    }

    state parse_dq {
        pkt.extract(hdr.l5);
        transition parse_meta;
    } 

    state parse_meta {
        pkt.extract(hdr.meta);
        transition accept;
    }
    
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
        /*this should be moved to control flow
        if (hdr.meta.rec.recirculation_flag == 0) {
            hdr.meta.setInvalid();
        }*/
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tunnel);
        pkt.emit(hdr.l4_port);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.l5);
        pkt.emit(hdr.meta);
    }
}

#endif