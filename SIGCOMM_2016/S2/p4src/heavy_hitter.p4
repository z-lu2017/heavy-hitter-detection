/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "includes/headers.p4"
#include "includes/parser.p4"


field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

action _drop() {
    drop();
}

action _noaction(){
    no_op();
}

header_type custom_metadata_t {
    fields {
        nhop_ipv4: 32;
        hash_val1: 16;
        hash_val2: 16;
        count_val1: 48;
        count_val2: 48;
        start_time1: 48;
        end_time1 : 48;
        delta1: 48;
        start_time2: 48;
        end_time2: 48;
        delta2: 48;
        meter_tag: 32;
    }
}
metadata custom_metadata_t custom_metadata;

action set_nhop(nhop_ipv4, port) {
    modify_field(custom_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

field_list hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    tcp.srcPort;
    tcp.dstPort;
}

field_list_calculation heavy_hitter_hash1 {
    input {
        hash_fields;
    }
    algorithm : csum16;
    output_width : 16;
}

field_list_calculation heavy_hitter_hash2 {
    input {
        hash_fields;
    }
    algorithm : crc16;
    output_width : 16;
}

register heavy_hitter_counter1{
    width : 48;
    instance_count : 16;
}

register heavy_hitter_counter2{
    width : 48;
    instance_count : 16;
}

action set_heavy_hitter_count() {
    // stores the hash of 5 tuples at hash_val1 - use as index
    modify_field_with_hash_based_offset(custom_metadata.hash_val1, 0,
                                        heavy_hitter_hash1, 16);
    // read from heavy_hitter_count1 at index hash_val1 and store in count_val1
    register_read(custom_metadata.count_val1, heavy_hitter_counter1, custom_metadata.hash_val1);
    // increment counter
    add_to_field(custom_metadata.count_val1, 1);
    // update counter
    register_write(heavy_hitter_counter1, custom_metadata.hash_val1, custom_metadata.count_val1);

    // repeat for hash function 2
    modify_field_with_hash_based_offset(custom_metadata.hash_val2, 0,
                                        heavy_hitter_hash2, 16);
    register_read(custom_metadata.count_val2, heavy_hitter_counter2, custom_metadata.hash_val2);
    add_to_field(custom_metadata.count_val2, 1);
    register_write(heavy_hitter_counter2, custom_metadata.hash_val2, custom_metadata.count_val2);
}

table set_heavy_hitter_count_table {
    actions {
        set_heavy_hitter_count;
    }
    size: 1;
}

table drop_heavy_hitter_table {
    actions { _drop; }
    size: 1;
}

table ipv4_lpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_nhop;
        _drop;
    }
    size: 1024;
}

table forward {
    reads {
        custom_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}

meter heavy_hitter_1{
    type: bytes;
    result: custom_metadata.meter_tag;
    instance_count: 16;
}

action m_action(meter_idx){
    execute_meter(heavy_hitter_1, meter_idx, custom_metadata.meter_tag);
}

table m_table {
  reads {
      ethernet.dstAddr: exact;
  }
  actions {
      m_action;
      _noaction;
  }
  size: 1024;
}

table m_filter {
    reads {
        custom_metadata.meter_tag: exact;
    }
    actions {
        _drop;
        _noaction;
    }
    size: 1024;
}


control ingress {
    apply(set_heavy_hitter_count_table);
    apply(ipv4_lpm);
    apply(forward);
    apply(m_table);
    apply(m_filter);
}

control egress {
    apply(send_frame);
}
