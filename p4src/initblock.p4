//Initialization block in ingress pipeline
#include "../config.h"

#ifndef _INITBLOCK_
#define _INITBLOCK_

control InitializationBlock(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {
        
        action forward(bit<9> port) {
            //ig_intr_tm_md.ucast_egress_port = port;
            hdr.meta.rec.egress_port = port;
        }

        action drop() {
            ig_intr_dprsr_md.drop_ctl = 1;
        }

        action set_flow_id(bit<16> flow_id) {
            hdr.meta.id.flow_id = flow_id;
        }

        @pragma stage 0
        table tb_forward {
            key = {
                ig_intr_md.ingress_port : exact;
            }
            actions = {
                forward;
                drop;
            }
            default_action = drop;
            size = 512;
        }

        @pragma stage 0
        table tb_flow_filter1 {
            key = {
                hdr.ethernet.dst : ternary;
                hdr.ethernet.src : ternary;
                hdr.ethernet.ether_type: ternary;
            }
            actions = {
                set_flow_id;
                NoAction;
            }
            default_action = NoAction();
            size = 512;
        }

        @pragma stage 0
        table tb_flow_filter2 {
            key = {
                hdr.ipv4.src : ternary;
                hdr.ipv4.dst : ternary;
                hdr.ipv4.protocol : ternary;
                hdr.l4_port.src_port : ternary;
                hdr.l4_port.dst_port : ternary;
            }
            actions = {
                set_flow_id;
                NoAction;
            }
            default_action = NoAction();
            size = 512;
        }

        @pragma stage 0
        table tb_flow_filter3 {
            key = {
                hdr.tunnel.dst_id : ternary;
            }
            actions = {
                set_flow_id;
                NoAction;
            }
            default_action = NoAction();
            size = 512;
        }

        apply {
            tb_forward.apply();
            if(ig_md.bitmap[BITWIDTH_L3] == 0) { //an L2 packet
                tb_flow_filter1.apply();
            } else if(ig_md.bitmap[BITWIDTH_L4] > 0) { //L4 packet
                tb_flow_filter2.apply();
            } else if(ig_md.bitmap[BITWIDTH_L3] == 1) { //tunnel
                tb_flow_filter3.apply();
            }
        }
}

#endif