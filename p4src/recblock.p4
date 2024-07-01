//Recirculation block in ingress and egress pipeline
#include "../config.h"

#ifndef _RECBLOCK_
#define _RECBLOCK_

control RecirculationBlock(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        action first_recirculate() {
            //hdr.meta.rec.egress_port = ig_intr_tm_md.ucast_egress_port;
            hdr.meta.rec.recirculation_flag = 1;
            ig_intr_tm_md.ucast_egress_port = PORT_RECIRCULATION;
        }

        action middle_recirculate() {
            ig_intr_tm_md.ucast_egress_port = PORT_RECIRCULATION;
        }

        action last_recirculate() {
            ig_intr_tm_md.ucast_egress_port = hdr.meta.rec.egress_port;
            hdr.meta.rec.recirculation_flag = 0;
        }

        action set_egress_port() {
            ig_intr_tm_md.ucast_egress_port = hdr.meta.rec.egress_port;

        }

        @pragma stage 11
        table tb_recirculation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.rec.iterations : exact;
            }            
            actions = {
                first_recirculate;
                middle_recirculate;
                last_recirculate;
                set_egress_port;
            }
            default_action = set_egress_port();
            size = 2048;
        }
        apply {
            if(hdr.meta.isValid()) {
                tb_recirculation.apply();
            }
        }
}

#endif