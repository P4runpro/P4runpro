#ifndef _EGRESS_
#define _EGRESS_

control SwitchEgress(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

        EgressRPB11() rpb11;
        EgressRPB12() rpb12;
        EgressRPB13() rpb13;
        EgressRPB14() rpb14;
        EgressRPB15() rpb15;
        EgressRPB16() rpb16;
        EgressRPB17() rpb17;
        EgressRPB18() rpb18;
        EgressRPB19() rpb19;
        EgressRPB20() rpb20;
        EgressRPB21() rpb21;
        EgressRPB22() rpb22;

        apply {
            rpb11.apply(hdr, eg_md, eg_intr_md, eg_intr_md_from_prsr, eg_intr_dprs_md, eg_intr_oport_md);
            rpb12.apply(hdr, eg_md, eg_intr_md, eg_intr_md_from_prsr, eg_intr_dprs_md, eg_intr_oport_md);
            rpb13.apply(hdr, eg_md, eg_intr_md, eg_intr_md_from_prsr, eg_intr_dprs_md, eg_intr_oport_md);
            rpb14.apply(hdr, eg_md, eg_intr_md, eg_intr_md_from_prsr, eg_intr_dprs_md, eg_intr_oport_md);
            rpb15.apply(hdr, eg_md, eg_intr_md, eg_intr_md_from_prsr, eg_intr_dprs_md, eg_intr_oport_md);
            rpb16.apply(hdr, eg_md, eg_intr_md, eg_intr_md_from_prsr, eg_intr_dprs_md, eg_intr_oport_md);
            rpb17.apply(hdr, eg_md, eg_intr_md, eg_intr_md_from_prsr, eg_intr_dprs_md, eg_intr_oport_md);
            rpb18.apply(hdr, eg_md, eg_intr_md, eg_intr_md_from_prsr, eg_intr_dprs_md, eg_intr_oport_md);
            rpb19.apply(hdr, eg_md, eg_intr_md, eg_intr_md_from_prsr, eg_intr_dprs_md, eg_intr_oport_md);
            rpb20.apply(hdr, eg_md, eg_intr_md, eg_intr_md_from_prsr, eg_intr_dprs_md, eg_intr_oport_md);
            rpb21.apply(hdr, eg_md, eg_intr_md, eg_intr_md_from_prsr, eg_intr_dprs_md, eg_intr_oport_md);
            rpb22.apply(hdr, eg_md, eg_intr_md, eg_intr_md_from_prsr, eg_intr_dprs_md, eg_intr_oport_md);
            if (hdr.meta.rec.recirculation_flag == 0) {
                hdr.meta.setInvalid();
            }
            else {
                hdr.meta.rec.iterations = hdr.meta.rec.iterations + 1;
            }
        }
}

#endif