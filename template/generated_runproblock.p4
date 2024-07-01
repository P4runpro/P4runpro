//RPB in ingress and egress pipeline
#include "../config.h"

#ifndef _RUNPROBLOCK_
#define _RUNPROBLOCK_


control IngressRPB1(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        Register<bit<32>, _>(65536) rpb1_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb1_register) rpb1_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb1_register) rpb1_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb1_register) rpb1_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb1_register) rpb1_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x18005,
            reversed    = true,
            msb         = false,
            extended    = true,
            init        = 0x0000,
            xor         = 0x0000
        ) poly_rpb1;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb1) hash1_rpb1;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb1) hash2_rpb1;

        //action for forwarding

        action rt() {           //return a packet to its sender
            bit<48> mac_tmp = hdr.ethernet.dst;
            hdr.ethernet.dst = hdr.ethernet.src;
            hdr.ethernet.src = mac_tmp;
            bit<32> ip_tmp = hdr.ipv4.dst;
            hdr.ipv4.dst = hdr.ipv4.src;
            hdr.ipv4.src = ip_tmp;
            //ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            hdr.meta.rec.egress_port = ig_intr_md.ingress_port;
        }

        action forward(bit<9> port)  {
            //ig_intr_tm_md.ucast_egress_port = port;
            hdr.meta.rec.egress_port = port;
        }
        
        action drop() {         //drop the packet
            ig_intr_dprsr_md.drop_ctl = 1;
        }

        action report() {
            //ig_intr_tm_md.ucast_egress_port = PORT_CPU;
            hdr.meta.rec.egress_port = PORT_CPU;
        }

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb1.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb1.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb1.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb1.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb1_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb1_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb1_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb1_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 1
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

                rt;
                drop;
                forward;
                report;
            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control IngressRPB2(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        Register<bit<32>, _>(65536) rpb2_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb2_register) rpb2_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb2_register) rpb2_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb2_register) rpb2_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb2_register) rpb2_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x18005,
            reversed    = false,
            msb         = false,
            extended    = true,
            init        = 0x0000,
            xor         = 0x0000
        ) poly_rpb2;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb2) hash1_rpb2;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb2) hash2_rpb2;

        //action for forwarding

        action rt() {           //return a packet to its sender
            bit<48> mac_tmp = hdr.ethernet.dst;
            hdr.ethernet.dst = hdr.ethernet.src;
            hdr.ethernet.src = mac_tmp;
            bit<32> ip_tmp = hdr.ipv4.dst;
            hdr.ipv4.dst = hdr.ipv4.src;
            hdr.ipv4.src = ip_tmp;
            //ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            hdr.meta.rec.egress_port = ig_intr_md.ingress_port;
        }

        action forward(bit<9> port)  {
            //ig_intr_tm_md.ucast_egress_port = port;
            hdr.meta.rec.egress_port = port;
        }
        
        action drop() {         //drop the packet
            ig_intr_dprsr_md.drop_ctl = 1;
        }

        action report() {
            //ig_intr_tm_md.ucast_egress_port = PORT_CPU;
            hdr.meta.rec.egress_port = PORT_CPU;
        }

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb2.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb2.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb2.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb2.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb2_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb2_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb2_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb2_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 2
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

                rt;
                drop;
                forward;
                report;
            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control IngressRPB3(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        Register<bit<32>, _>(65536) rpb3_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb3_register) rpb3_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb3_register) rpb3_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb3_register) rpb3_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb3_register) rpb3_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x18005,
            reversed    = false,
            msb         = false,
            extended    = true,
            init        = 0x800D,
            xor         = 0x0000
        ) poly_rpb3;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb3) hash1_rpb3;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb3) hash2_rpb3;

        //action for forwarding

        action rt() {           //return a packet to its sender
            bit<48> mac_tmp = hdr.ethernet.dst;
            hdr.ethernet.dst = hdr.ethernet.src;
            hdr.ethernet.src = mac_tmp;
            bit<32> ip_tmp = hdr.ipv4.dst;
            hdr.ipv4.dst = hdr.ipv4.src;
            hdr.ipv4.src = ip_tmp;
            //ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            hdr.meta.rec.egress_port = ig_intr_md.ingress_port;
        }

        action forward(bit<9> port)  {
            //ig_intr_tm_md.ucast_egress_port = port;
            hdr.meta.rec.egress_port = port;
        }
        
        action drop() {         //drop the packet
            ig_intr_dprsr_md.drop_ctl = 1;
        }

        action report() {
            //ig_intr_tm_md.ucast_egress_port = PORT_CPU;
            hdr.meta.rec.egress_port = PORT_CPU;
        }

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb3.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb3.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb3.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb3.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb3_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb3_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb3_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb3_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 3
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

                rt;
                drop;
                forward;
                report;
            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control IngressRPB4(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        Register<bit<32>, _>(65536) rpb4_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb4_register) rpb4_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb4_register) rpb4_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb4_register) rpb4_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb4_register) rpb4_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x10589,
            reversed    = false,
            msb         = false,
            extended    = true,
            init        = 0x0001,
            xor         = 0x0001
        ) poly_rpb4;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb4) hash1_rpb4;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb4) hash2_rpb4;

        //action for forwarding

        action rt() {           //return a packet to its sender
            bit<48> mac_tmp = hdr.ethernet.dst;
            hdr.ethernet.dst = hdr.ethernet.src;
            hdr.ethernet.src = mac_tmp;
            bit<32> ip_tmp = hdr.ipv4.dst;
            hdr.ipv4.dst = hdr.ipv4.src;
            hdr.ipv4.src = ip_tmp;
            //ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            hdr.meta.rec.egress_port = ig_intr_md.ingress_port;
        }

        action forward(bit<9> port)  {
            //ig_intr_tm_md.ucast_egress_port = port;
            hdr.meta.rec.egress_port = port;
        }
        
        action drop() {         //drop the packet
            ig_intr_dprsr_md.drop_ctl = 1;
        }

        action report() {
            //ig_intr_tm_md.ucast_egress_port = PORT_CPU;
            hdr.meta.rec.egress_port = PORT_CPU;
        }

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb4.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb4.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb4.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb4.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb4_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb4_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb4_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb4_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 4
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

                rt;
                drop;
                forward;
                report;
            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control IngressRPB5(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        Register<bit<32>, _>(65536) rpb5_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb5_register) rpb5_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb5_register) rpb5_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb5_register) rpb5_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb5_register) rpb5_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x13D65,
            reversed    = true,
            msb         = false,
            extended    = true,
            init        = 0xFFFF,
            xor         = 0xFFFF
        ) poly_rpb5;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb5) hash1_rpb5;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb5) hash2_rpb5;

        //action for forwarding

        action rt() {           //return a packet to its sender
            bit<48> mac_tmp = hdr.ethernet.dst;
            hdr.ethernet.dst = hdr.ethernet.src;
            hdr.ethernet.src = mac_tmp;
            bit<32> ip_tmp = hdr.ipv4.dst;
            hdr.ipv4.dst = hdr.ipv4.src;
            hdr.ipv4.src = ip_tmp;
            //ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            hdr.meta.rec.egress_port = ig_intr_md.ingress_port;
        }

        action forward(bit<9> port)  {
            //ig_intr_tm_md.ucast_egress_port = port;
            hdr.meta.rec.egress_port = port;
        }
        
        action drop() {         //drop the packet
            ig_intr_dprsr_md.drop_ctl = 1;
        }

        action report() {
            //ig_intr_tm_md.ucast_egress_port = PORT_CPU;
            hdr.meta.rec.egress_port = PORT_CPU;
        }

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb5.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb5.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb5.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb5.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb5_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb5_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb5_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb5_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 5
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

                rt;
                drop;
                forward;
                report;
            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control IngressRPB6(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        Register<bit<32>, _>(65536) rpb6_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb6_register) rpb6_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb6_register) rpb6_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb6_register) rpb6_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb6_register) rpb6_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x13D65,
            reversed    = false,
            msb         = false,
            extended    = true,
            init        = 0xFFFF,
            xor         = 0xFFFF
        ) poly_rpb6;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb6) hash1_rpb6;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb6) hash2_rpb6;

        //action for forwarding

        action rt() {           //return a packet to its sender
            bit<48> mac_tmp = hdr.ethernet.dst;
            hdr.ethernet.dst = hdr.ethernet.src;
            hdr.ethernet.src = mac_tmp;
            bit<32> ip_tmp = hdr.ipv4.dst;
            hdr.ipv4.dst = hdr.ipv4.src;
            hdr.ipv4.src = ip_tmp;
            //ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            hdr.meta.rec.egress_port = ig_intr_md.ingress_port;
        }

        action forward(bit<9> port)  {
            //ig_intr_tm_md.ucast_egress_port = port;
            hdr.meta.rec.egress_port = port;
        }
        
        action drop() {         //drop the packet
            ig_intr_dprsr_md.drop_ctl = 1;
        }

        action report() {
            //ig_intr_tm_md.ucast_egress_port = PORT_CPU;
            hdr.meta.rec.egress_port = PORT_CPU;
        }

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb6.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb6.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb6.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb6.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb6_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb6_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb6_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb6_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 6
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

                rt;
                drop;
                forward;
                report;
            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control IngressRPB7(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        Register<bit<32>, _>(65536) rpb7_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb7_register) rpb7_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb7_register) rpb7_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb7_register) rpb7_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb7_register) rpb7_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x11021,
            reversed    = false,
            msb         = false,
            extended    = true,
            init        = 0x0000,
            xor         = 0xFFFF
        ) poly_rpb7;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb7) hash1_rpb7;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb7) hash2_rpb7;

        //action for forwarding

        action rt() {           //return a packet to its sender
            bit<48> mac_tmp = hdr.ethernet.dst;
            hdr.ethernet.dst = hdr.ethernet.src;
            hdr.ethernet.src = mac_tmp;
            bit<32> ip_tmp = hdr.ipv4.dst;
            hdr.ipv4.dst = hdr.ipv4.src;
            hdr.ipv4.src = ip_tmp;
            //ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            hdr.meta.rec.egress_port = ig_intr_md.ingress_port;
        }

        action forward(bit<9> port)  {
            //ig_intr_tm_md.ucast_egress_port = port;
            hdr.meta.rec.egress_port = port;
        }
        
        action drop() {         //drop the packet
            ig_intr_dprsr_md.drop_ctl = 1;
        }

        action report() {
            //ig_intr_tm_md.ucast_egress_port = PORT_CPU;
            hdr.meta.rec.egress_port = PORT_CPU;
        }

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb7.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb7.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb7.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb7.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb7_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb7_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb7_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb7_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 7
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

                rt;
                drop;
                forward;
                report;
            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control IngressRPB8(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        Register<bit<32>, _>(65536) rpb8_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb8_register) rpb8_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb8_register) rpb8_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb8_register) rpb8_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb8_register) rpb8_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x18005,
            reversed    = true,
            msb         = false,
            extended    = true,
            init        = 0xFFFF,
            xor         = 0xFFFF
        ) poly_rpb8;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb8) hash1_rpb8;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb8) hash2_rpb8;

        //action for forwarding

        action rt() {           //return a packet to its sender
            bit<48> mac_tmp = hdr.ethernet.dst;
            hdr.ethernet.dst = hdr.ethernet.src;
            hdr.ethernet.src = mac_tmp;
            bit<32> ip_tmp = hdr.ipv4.dst;
            hdr.ipv4.dst = hdr.ipv4.src;
            hdr.ipv4.src = ip_tmp;
            //ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            hdr.meta.rec.egress_port = ig_intr_md.ingress_port;
        }

        action forward(bit<9> port)  {
            //ig_intr_tm_md.ucast_egress_port = port;
            hdr.meta.rec.egress_port = port;
        }
        
        action drop() {         //drop the packet
            ig_intr_dprsr_md.drop_ctl = 1;
        }

        action report() {
            //ig_intr_tm_md.ucast_egress_port = PORT_CPU;
            hdr.meta.rec.egress_port = PORT_CPU;
        }

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb8.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb8.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb8.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb8.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb8_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb8_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb8_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb8_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 8
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

                rt;
                drop;
                forward;
                report;
            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control IngressRPB9(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        Register<bit<32>, _>(65536) rpb9_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb9_register) rpb9_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb9_register) rpb9_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb9_register) rpb9_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb9_register) rpb9_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x11021,
            reversed    = true,
            msb         = false,
            extended    = true,
            init        = 0xFFFF,
            xor         = 0x0000
        ) poly_rpb9;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb9) hash1_rpb9;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb9) hash2_rpb9;

        //action for forwarding

        action rt() {           //return a packet to its sender
            bit<48> mac_tmp = hdr.ethernet.dst;
            hdr.ethernet.dst = hdr.ethernet.src;
            hdr.ethernet.src = mac_tmp;
            bit<32> ip_tmp = hdr.ipv4.dst;
            hdr.ipv4.dst = hdr.ipv4.src;
            hdr.ipv4.src = ip_tmp;
            //ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            hdr.meta.rec.egress_port = ig_intr_md.ingress_port;
        }

        action forward(bit<9> port)  {
            //ig_intr_tm_md.ucast_egress_port = port;
            hdr.meta.rec.egress_port = port;
        }
        
        action drop() {         //drop the packet
            ig_intr_dprsr_md.drop_ctl = 1;
        }

        action report() {
            //ig_intr_tm_md.ucast_egress_port = PORT_CPU;
            hdr.meta.rec.egress_port = PORT_CPU;
        }

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb9.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb9.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb9.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb9.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb9_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb9_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb9_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb9_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 9
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

                rt;
                drop;
                forward;
                report;
            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control IngressRPB10(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        Register<bit<32>, _>(65536) rpb10_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb10_register) rpb10_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb10_register) rpb10_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb10_register) rpb10_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb10_register) rpb10_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x11021,
            reversed    = true,
            msb         = false,
            extended    = true,
            init        = 0x554D,
            xor         = 0x0000
        ) poly_rpb10;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb10) hash1_rpb10;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb10) hash2_rpb10;

        //action for forwarding

        action rt() {           //return a packet to its sender
            bit<48> mac_tmp = hdr.ethernet.dst;
            hdr.ethernet.dst = hdr.ethernet.src;
            hdr.ethernet.src = mac_tmp;
            bit<32> ip_tmp = hdr.ipv4.dst;
            hdr.ipv4.dst = hdr.ipv4.src;
            hdr.ipv4.src = ip_tmp;
            //ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            hdr.meta.rec.egress_port = ig_intr_md.ingress_port;
        }

        action forward(bit<9> port)  {
            //ig_intr_tm_md.ucast_egress_port = port;
            hdr.meta.rec.egress_port = port;
        }
        
        action drop() {         //drop the packet
            ig_intr_dprsr_md.drop_ctl = 1;
        }

        action report() {
            //ig_intr_tm_md.ucast_egress_port = PORT_CPU;
            hdr.meta.rec.egress_port = PORT_CPU;
        }

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb10.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb10.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb10.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb10.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb10_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb10_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb10_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb10_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 10
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

                rt;
                drop;
                forward;
                report;
            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control EgressRPB11(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

        Register<bit<32>, _>(65536) rpb11_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb11_register) rpb11_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb11_register) rpb11_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb11_register) rpb11_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb11_register) rpb11_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x18BB7,
            reversed    = false,
            msb         = false,
            extended    = true,
            init        = 0x0000,
            xor         = 0x0000
        ) poly_rpb11;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb11) hash1_rpb11;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb11) hash2_rpb11;

        //action for forwarding

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb11.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb11.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb11.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb11.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction
        action extract_egintrmddeqtimedelta_har() {
            hdr.meta.reg.har = (bit<32>)eg_intr_md.deq_timedelta;
        }

        action modify_hdripv4ecn_sar() {
            hdr.ipv4.ecn = (bit<2>)hdr.meta.reg.sar;
        }

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb11_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb11_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb11_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb11_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 0
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_egintrmddeqtimedelta_har;
                modify_hdripv4ecn_sar;
                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control EgressRPB12(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

        Register<bit<32>, _>(65536) rpb12_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb12_register) rpb12_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb12_register) rpb12_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb12_register) rpb12_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb12_register) rpb12_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x1A097,
            reversed    = false,
            msb         = false,
            extended    = true,
            init        = 0x0000,
            xor         = 0xFFFF
        ) poly_rpb12;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb12) hash1_rpb12;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb12) hash2_rpb12;

        //action for forwarding

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb12.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb12.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb12.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb12.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction
        action extract_egintrmddeqtimedelta_har() {
            hdr.meta.reg.har = (bit<32>)eg_intr_md.deq_timedelta;
        }

        action modify_hdripv4ecn_sar() {
            hdr.ipv4.ecn = (bit<2>)hdr.meta.reg.sar;
        }

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb12_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb12_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb12_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb12_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 1
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_egintrmddeqtimedelta_har;
                modify_hdripv4ecn_sar;
                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control EgressRPB13(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

        Register<bit<32>, _>(65536) rpb13_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb13_register) rpb13_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb13_register) rpb13_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb13_register) rpb13_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb13_register) rpb13_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x18005,
            reversed    = true,
            msb         = false,
            extended    = true,
            init        = 0x0000,
            xor         = 0xFFFF
        ) poly_rpb13;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb13) hash1_rpb13;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb13) hash2_rpb13;

        //action for forwarding

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb13.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb13.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb13.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb13.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction
        action extract_egintrmddeqtimedelta_har() {
            hdr.meta.reg.har = (bit<32>)eg_intr_md.deq_timedelta;
        }

        action modify_hdripv4ecn_sar() {
            hdr.ipv4.ecn = (bit<2>)hdr.meta.reg.sar;
        }

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb13_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb13_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb13_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb13_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 2
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_egintrmddeqtimedelta_har;
                modify_hdripv4ecn_sar;
                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control EgressRPB14(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

        Register<bit<32>, _>(65536) rpb14_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb14_register) rpb14_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb14_register) rpb14_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb14_register) rpb14_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb14_register) rpb14_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x11021,
            reversed    = true,
            msb         = false,
            extended    = true,
            init        = 0x0000,
            xor         = 0xFFFF
        ) poly_rpb14;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb14) hash1_rpb14;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb14) hash2_rpb14;

        //action for forwarding

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb14.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb14.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb14.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb14.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction
        action extract_egintrmddeqtimedelta_har() {
            hdr.meta.reg.har = (bit<32>)eg_intr_md.deq_timedelta;
        }

        action modify_hdripv4ecn_sar() {
            hdr.ipv4.ecn = (bit<2>)hdr.meta.reg.sar;
        }

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb14_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb14_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb14_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb14_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 3
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_egintrmddeqtimedelta_har;
                modify_hdripv4ecn_sar;
                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control EgressRPB15(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

        Register<bit<32>, _>(65536) rpb15_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb15_register) rpb15_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb15_register) rpb15_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb15_register) rpb15_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb15_register) rpb15_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x11021,
            reversed    = false,
            msb         = false,
            extended    = true,
            init        = 0x0000,
            xor         = 0x0000
        ) poly_rpb15;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb15) hash1_rpb15;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb15) hash2_rpb15;

        //action for forwarding

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb15.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb15.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb15.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb15.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction
        action extract_egintrmddeqtimedelta_har() {
            hdr.meta.reg.har = (bit<32>)eg_intr_md.deq_timedelta;
        }

        action modify_hdripv4ecn_sar() {
            hdr.ipv4.ecn = (bit<2>)hdr.meta.reg.sar;
        }

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb15_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb15_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb15_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb15_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 4
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_egintrmddeqtimedelta_har;
                modify_hdripv4ecn_sar;
                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control EgressRPB16(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

        Register<bit<32>, _>(65536) rpb16_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb16_register) rpb16_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb16_register) rpb16_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb16_register) rpb16_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb16_register) rpb16_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x18005,
            reversed    = true,
            msb         = false,
            extended    = true,
            init        = 0xFFFF,
            xor         = 0x0000
        ) poly_rpb16;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb16) hash1_rpb16;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb16) hash2_rpb16;

        //action for forwarding

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb16.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb16.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb16.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb16.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction
        action extract_egintrmddeqtimedelta_har() {
            hdr.meta.reg.har = (bit<32>)eg_intr_md.deq_timedelta;
        }

        action modify_hdripv4ecn_sar() {
            hdr.ipv4.ecn = (bit<2>)hdr.meta.reg.sar;
        }

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb16_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb16_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb16_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb16_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 5
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_egintrmddeqtimedelta_har;
                modify_hdripv4ecn_sar;
                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control EgressRPB17(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

        Register<bit<32>, _>(65536) rpb17_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb17_register) rpb17_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb17_register) rpb17_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb17_register) rpb17_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb17_register) rpb17_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x11021,
            reversed    = true,
            msb         = false,
            extended    = true,
            init        = 0x0000,
            xor         = 0x0000
        ) poly_rpb17;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb17) hash1_rpb17;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb17) hash2_rpb17;

        //action for forwarding

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb17.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb17.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb17.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb17.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction
        action extract_egintrmddeqtimedelta_har() {
            hdr.meta.reg.har = (bit<32>)eg_intr_md.deq_timedelta;
        }

        action modify_hdripv4ecn_sar() {
            hdr.ipv4.ecn = (bit<2>)hdr.meta.reg.sar;
        }

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb17_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb17_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb17_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb17_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 6
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_egintrmddeqtimedelta_har;
                modify_hdripv4ecn_sar;
                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control EgressRPB18(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

        Register<bit<32>, _>(65536) rpb18_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb18_register) rpb18_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb18_register) rpb18_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb18_register) rpb18_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb18_register) rpb18_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x11021,
            reversed    = false,
            msb         = false,
            extended    = true,
            init        = 0xFFFF,
            xor         = 0x0000
        ) poly_rpb18;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb18) hash1_rpb18;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb18) hash2_rpb18;

        //action for forwarding

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb18.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb18.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb18.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb18.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction
        action extract_egintrmddeqtimedelta_har() {
            hdr.meta.reg.har = (bit<32>)eg_intr_md.deq_timedelta;
        }

        action modify_hdripv4ecn_sar() {
            hdr.ipv4.ecn = (bit<2>)hdr.meta.reg.sar;
        }

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb18_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb18_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb18_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb18_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 7
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_egintrmddeqtimedelta_har;
                modify_hdripv4ecn_sar;
                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control EgressRPB19(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

        Register<bit<32>, _>(65536) rpb19_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb19_register) rpb19_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb19_register) rpb19_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb19_register) rpb19_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb19_register) rpb19_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x11021,
            reversed    = false,
            msb         = false,
            extended    = true,
            init        = 0x1D0F,
            xor         = 0x0000
        ) poly_rpb19;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb19) hash1_rpb19;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb19) hash2_rpb19;

        //action for forwarding

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb19.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb19.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb19.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb19.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction
        action extract_egintrmddeqtimedelta_har() {
            hdr.meta.reg.har = (bit<32>)eg_intr_md.deq_timedelta;
        }

        action modify_hdripv4ecn_sar() {
            hdr.ipv4.ecn = (bit<2>)hdr.meta.reg.sar;
        }

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb19_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb19_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb19_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb19_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 8
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_egintrmddeqtimedelta_har;
                modify_hdripv4ecn_sar;
                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control EgressRPB20(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

        Register<bit<32>, _>(65536) rpb20_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb20_register) rpb20_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb20_register) rpb20_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb20_register) rpb20_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb20_register) rpb20_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x1C867,
            reversed    = false,
            msb         = false,
            extended    = true,
            init        = 0xFFFF,
            xor         = 0x0000
        ) poly_rpb20;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb20) hash1_rpb20;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb20) hash2_rpb20;

        //action for forwarding

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb20.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb20.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb20.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb20.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction
        action extract_egintrmddeqtimedelta_har() {
            hdr.meta.reg.har = (bit<32>)eg_intr_md.deq_timedelta;
        }

        action modify_hdripv4ecn_sar() {
            hdr.ipv4.ecn = (bit<2>)hdr.meta.reg.sar;
        }

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb20_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb20_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb20_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb20_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 9
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_egintrmddeqtimedelta_har;
                modify_hdripv4ecn_sar;
                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control EgressRPB21(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

        Register<bit<32>, _>(65536) rpb21_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb21_register) rpb21_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb21_register) rpb21_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb21_register) rpb21_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb21_register) rpb21_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x11021,
            reversed    = true,
            msb         = false,
            extended    = true,
            init        = 0x89EC,
            xor         = 0x0000
        ) poly_rpb21;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb21) hash1_rpb21;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb21) hash2_rpb21;

        //action for forwarding

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb21.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb21.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb21.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb21.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction
        action extract_egintrmddeqtimedelta_har() {
            hdr.meta.reg.har = (bit<32>)eg_intr_md.deq_timedelta;
        }

        action modify_hdripv4ecn_sar() {
            hdr.ipv4.ecn = (bit<2>)hdr.meta.reg.sar;
        }

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb21_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb21_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb21_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb21_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 10
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_egintrmddeqtimedelta_har;
                modify_hdripv4ecn_sar;
                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}
control EgressRPB22(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

        Register<bit<32>, _>(65536) rpb22_register;
        RegisterAction<bit<32>, _, bit<32>>(rpb22_register) rpb22_salu_op1 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value + hdr.meta.reg.sar;
                }
                else {
                    value = value - hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb22_register) rpb22_salu_op2 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 0) {
                    value = value & hdr.meta.reg.sar;
                    result = value;
                }
                else {
                    result = value;
                    value = value | hdr.meta.reg.sar;
                }
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb22_register) rpb22_salu_op3 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.param.salu_flag == 1) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };

        RegisterAction<bit<32>, _, bit<32>>(rpb22_register) rpb22_salu_op4 = {
            void apply(inout bit<32> value, out bit<32> result) {
                if ( hdr.meta.reg.sar > value) {
                    value = hdr.meta.reg.sar;
                }
                result = value;
            }
        };
        
        //CRC hash polynomial which need to be different in every stage
        CRCPolynomial<bit<16>>(
            coeff       = 0x11021,
            reversed    = true,
            msb         = false,
            extended    = true,
            init        = 0xC6C6,
            xor         = 0x0000
        ) poly_rpb22;

        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb22) hash1_rpb22;
        Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_rpb22) hash2_rpb22;

        //action for forwarding

        //action for branch
        action set_branch_id(bit<8> branch_id) {
            hdr.meta.id.branch_id = branch_id;
        }

        //action for hash
        action hash_5_tuple() {
            hdr.meta.reg.har[15:0] = hash1_rpb22.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization() {
            hdr.meta.reg.har[15:0] = hash2_rpb22.get({
                hdr.meta.reg.har
            });
        }

        action hash_5_tuple_mem() {
            hdr.meta.reg.mar[15:0] = hash1_rpb22.get({
                hdr.ipv4.src, 
                hdr.ipv4.dst, 
                hdr.l4_port.src_port, 
                hdr.l4_port.dst_port, 
                hdr.ipv4.protocol
            });
        }

        action hash_customization_mem() {
            hdr.meta.reg.mar[15:0] = hash2_rpb22.get({
                hdr.meta.reg.har
            });
        }

        //action for header interaction
        action extract_egintrmddeqtimedelta_har() {
            hdr.meta.reg.har = (bit<32>)eg_intr_md.deq_timedelta;
        }

        action modify_hdripv4ecn_sar() {
            hdr.ipv4.ecn = (bit<2>)hdr.meta.reg.sar;
        }

        action extract_hdrl5op_har() {
            hdr.meta.reg.har = hdr.l5.op;
        }
        
        action extract_hdrl5key1_sar() {
            hdr.meta.reg.sar = hdr.l5.key1;
        }

        action extract_hdrl5key2_mar() {
            hdr.meta.reg.mar = hdr.l5.key2;
        }

        action extract_hdrtcptcp4thword_sar() {
            hdr.meta.reg.sar = hdr.tcp.tcp4thword;
        }

        action extract_hdripv4totallen_sar() {
            hdr.meta.reg.sar = (bit<32>)hdr.ipv4.total_len;
        }

        action extract_hdrl5key3_sar() {
            hdr.meta.reg.sar = hdr.l5.key3;
        }

        action modify_hdrl5key3_sar() {
            hdr.l5.key3 = hdr.meta.reg.sar;
        }

        action modify_hdripv4dst_sar() {
            hdr.ipv4.dst = hdr.meta.reg.sar;
        }

        //action for SALU operaiton
        action salu_add_sub() {
            hdr.meta.reg.sar = rpb22_salu_op1.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_and_or() {
            hdr.meta.reg.sar = rpb22_salu_op2.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_read_write() {
            hdr.meta.reg.sar = rpb22_salu_op3.execute((bit<16>)hdr.meta.param.physical_address);
        }
        action salu_max() {
            hdr.meta.reg.sar = rpb22_salu_op4.execute((bit<16>)hdr.meta.param.physical_address);
        }

        //action for PHV ALU operation

        action address_translation_mask(bit<32> mask) {
            hdr.meta.reg.mar = hdr.meta.reg.mar & mask;
        }

        action address_translation_offset(bit<32> offset, bit<8> flag) {
            hdr.meta.param.physical_address = hdr.meta.reg.mar + offset;
            hdr.meta.param.salu_flag = flag;
        }
        
        action loadi_mar(bit<32> i) {
            hdr.meta.reg.mar = i;
        }

        action backup() {
            hdr.meta.param.backup1 = hdr.meta.reg.mar;
            hdr.meta.param.backup2 = hdr.meta.reg.sar;
            hdr.meta.param.backup3 = hdr.meta.reg.har;
        }

        action recover1() {
             hdr.meta.reg.mar = hdr.meta.param.backup1;
        }

        action recover2() {
             hdr.meta.reg.sar = hdr.meta.param.backup2;
        }

        action recover3() {
             hdr.meta.reg.har = hdr.meta.param.backup3;
        }

        action loadi_sar(bit<32> i) {
            hdr.meta.reg.sar = i;
        }

        action loadi_har(bit<32> i) {
            hdr.meta.reg.har = i;
        }

        action add_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.sar;
        }

        action add_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar + hdr.meta.reg.har;
        }

        action add_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.mar;
        }

        action add_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar + hdr.meta.reg.har;
        }

        action add_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.mar;
        }

        action add_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har + hdr.meta.reg.sar;
        }

        action and_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.sar;
        }

        action and_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar & hdr.meta.reg.har;
        }

        action and_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.mar;
        }

        action and_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar & hdr.meta.reg.har;
        }

        action and_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.mar;
        }

        action and_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har & hdr.meta.reg.sar;
        }

        action or_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.sar;
        }

        action or_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar | hdr.meta.reg.har;
        }

        action or_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.mar;
        }

        action or_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar | hdr.meta.reg.har;
        }

        action or_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.mar;
        }

        action or_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har | hdr.meta.reg.sar;
        }

        action xor_mar_sar() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.sar;
        }

        action xor_mar_har() {
            hdr.meta.reg.mar = hdr.meta.reg.mar ^ hdr.meta.reg.har;
        }

        action xor_sar_mar() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.mar;
        }

        action xor_sar_har() {
            hdr.meta.reg.sar = hdr.meta.reg.sar ^ hdr.meta.reg.har;
        }

        action xor_har_mar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.mar;
        }

        action xor_har_sar() {
            hdr.meta.reg.har = hdr.meta.reg.har ^ hdr.meta.reg.sar;
        }

        action max_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action max_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar > hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action max_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action max_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar > hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action max_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action max_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har > hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        action min_mar_sar() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.sar ? hdr.meta.reg.mar : hdr.meta.reg.sar);
        }

        action min_mar_har() {
            hdr.meta.reg.mar = (hdr.meta.reg.mar < hdr.meta.reg.har ? hdr.meta.reg.mar : hdr.meta.reg.har);
        }

        action min_sar_mar() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.mar ? hdr.meta.reg.sar : hdr.meta.reg.mar);
        }

        action min_sar_har() {
            hdr.meta.reg.sar = (hdr.meta.reg.sar < hdr.meta.reg.har ? hdr.meta.reg.sar : hdr.meta.reg.har);
        }

        action min_har_mar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.mar ? hdr.meta.reg.har : hdr.meta.reg.mar);
        }

        action min_har_sar() {
            hdr.meta.reg.har = (hdr.meta.reg.har < hdr.meta.reg.sar ? hdr.meta.reg.har : hdr.meta.reg.sar);
        }

        @pragma stage 11
        table tb_operation {
            key = {
                hdr.meta.id.flow_id : exact;
                hdr.meta.id.branch_id : exact;
                hdr.meta.rec.iterations : exact;
                hdr.meta.reg.mar : ternary;
                hdr.meta.reg.sar : ternary;
                hdr.meta.reg.har : ternary;
            }
            actions = {
                NoAction;

                address_translation_mask;
                address_translation_offset;

                //Due to the VLIW constraints, we disenable the register backup by default in our prototype
                //It can be enabled by deletling some other actions
                //backup;
                //recover1;
                //recover2;
                //recover3;

                hash_5_tuple;
                hash_5_tuple_mem;
                hash_customization;
                hash_customization_mem;

                set_branch_id;

                extract_egintrmddeqtimedelta_har;
                modify_hdripv4ecn_sar;
                extract_hdrl5op_har;
                extract_hdrl5key1_sar;
                extract_hdrl5key2_mar;
                extract_hdrtcptcp4thword_sar;
                extract_hdripv4totallen_sar;
                extract_hdrl5key3_sar;
                modify_hdrl5key3_sar;
                modify_hdripv4dst_sar;

                salu_add_sub;
                salu_and_or;
                salu_read_write;
                salu_max;
                
                loadi_mar;
                loadi_sar;
                loadi_har;
                add_mar_sar;
                add_mar_har;
                add_sar_mar;
                add_sar_har;
                add_har_mar;
                add_har_sar;
                and_mar_sar;
                and_mar_har;
                and_sar_mar;
                and_sar_har;
                and_har_mar;
                and_har_sar;
                or_mar_sar;
                or_mar_har;
                or_sar_mar;
                or_sar_har;
                or_har_mar;
                or_har_sar;
                xor_mar_sar;
                xor_mar_har;
                xor_sar_mar;
                xor_sar_har;
                xor_har_mar;
                xor_har_sar;
                max_mar_sar;
                max_mar_har;
                max_sar_mar;
                max_sar_har;
                max_har_mar;
                max_har_sar;
                min_mar_sar;
                min_mar_har;
                min_sar_mar;
                min_sar_har;
                min_har_mar;
                min_har_sar;

            }
            default_action = NoAction();
            size = 2048;
        }

        apply{
            if(hdr.meta.isValid()) {
                tb_operation.apply();
            }
        }
}

#endif