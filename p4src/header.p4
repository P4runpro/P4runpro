//Header and metadata definition
#include "../config.h"

#ifndef _HEADER_
#define _HEADER_

header ethernet_h {
    bit<48> dst;
    bit<48> src;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    bit<12> vid;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<6> diffserv;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<1> rec;
    bit<2> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src;
    bit<32> dst;
}

// unify the l4_port for hash operation
header l4_port_h {
    bit<16> src_port;
    bit<16> dst_port;
}

header tcp_h {
    //bit<16> src_port;
    //bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    /*
    bit<4> data_offset;
    bit<4> res;
    bit<1> cwr;
    bit<1> ece;
    bit<1> urg;
    bit<1> ack;
    bit<1> psh;
    bit<1> rst;
    bit<1> syn;
    bit<1> fin;
    bit<16> window;
    */
    bit<32> tcp4thword;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    //bit<16> src_port;
    //bit<16> dst_port;
    bit<16> hdr_lenght;
    bit<16> checksum;
}

header tunnel_h {
    bit<16> dst_id;
}

/*These user defined L5 header can be unified*/
header netcache_h {
    bit<8> op;
    bit<32> key;
    bit<32> value;
}

header cacl_h {
    bit<8> op;
    bit<32> opA;
    bit<32> opB;
    bit<32> res;
}

header dqacc_h {
    bit<8> op;
    bit<32> key;
}

header l5_header_h {
    bit<32> op;
    bit<32> key1;
    bit<32> key2;
    bit<32> key3;
}

struct register_t {
    bit<32> har;
    bit<32> mar;
    bit<32> sar; 
}

struct id_t {
    bit<16> flow_id;
    bit<8> branch_id;
}



struct parameter_t {
    bit<32> physical_address;
    bit<8> salu_flag;
    bit<32> backup1;
    bit<32> backup2;
    bit<32> backup3;
}

struct recirculation_t {
    bit<7> recirculation_flag;
    bit<9> egress_port;
    bit<8> iterations;
}

@flexible
header briged_metadata_h {
    register_t reg;
    id_t id;
    parameter_t param;
    recirculation_t rec;
    bit<8> ignore_me;
}

struct header_t {
    ethernet_h ethernet;
    vlan_tag_h vlan;
    ipv4_h ipv4;
    tunnel_h tunnel;
    l4_port_h l4_port;
    tcp_h tcp;
    udp_h udp;
    l5_header_h l5;
    briged_metadata_h meta;
}

struct ig_metadata_t {
    bit<16> physical_idx;
    bit<BITMAPWIDTH> bitmap;
}

struct eg_metadata_t {
}

#endif