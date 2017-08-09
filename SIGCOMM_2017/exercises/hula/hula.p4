/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_HULA = 0x2345;

#define MAX_HOPS  9
#define TOR_NUM   32
#define TOR_NUM_1 33

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<15> qdepth_t;
typedef bit<32> digest_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header srcRoute_t {
    bit<1>    bos;
    bit<15>   port;
}

header hula_t {
    bit<1>   dir;
    qdepth_t qdepth;
    digest_t digest;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<32> index;
    bit<16> hash;
    qdepth_t old_qdepth;
}

struct headers {
    ethernet_t              ethernet;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
    hula_t                  hula;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ParserImpl(packet_in packet,
                  out headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_HULA : parse_hula;
            TYPE_IPV4 : parse_ipv4;
            default   : accept;
        }
    }

    state parse_hula {
        packet.extract(hdr.hula);
        transition parse_srcRouting;
    }

    state parse_srcRouting {
        packet.extract(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos) {
            1       : parse_ipv4;
            default : parse_srcRouting;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control verifyChecksum(in headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    /* This action will drop packets */
    action drop() {
        mark_to_drop();
    }

    action nop() {
    }
    
    action srcRoute_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }

    register<qdepth_t>(TOR_NUM) srcindex_qdepth_reg; 
    register<digest_t>(TOR_NUM) srcindex_digest_reg; 
    register<bit<16>>(65536) flow_port_reg; 

    action hula_dst(bit<32> index) {
        /* pick min */
        meta.index = index;
    }

    register<bit<16>>(TOR_NUM) dstindex_nhop_reg; 
    action hula_set_nhop(bit<32> index) {
        dstindex_nhop_reg.write(index, (bit<16>)standard_metadata.ingress_port); 
    }

    action update_ttl(){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action hula_get_nhop(bit<32> index){
       bit<16> tmp;
       dstindex_nhop_reg.read(tmp, index); 
       standard_metadata.egress_spec = (bit<9>)tmp;
    }

    action set_dmac(macAddr_t dstAddr){
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        update_ttl(); 
    }

    /* hula_dst if dstAddr = this switch
     * index is set based on srcAddr
     * srcRoute_nhop otherwise
     */
    table hula_fwd {
        key = {
            hdr.ipv4.dstAddr: exact;
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            hula_dst;
            srcRoute_nhop;
        }
        default_action = srcRoute_nhop;
        size = TOR_NUM_1; // TOR_NUM + 1
    }

    /* hula_set_nhop otherwise
       index is set based on dstAddr */
    table hula_bwd {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            hula_set_nhop;
        }
        size = TOR_NUM;
    }

    /* hula_src if srcAddr = this switch */
    table hula_src {
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            drop;
            srcRoute_nhop;
        }
        default_action = srcRoute_nhop;
        size = 2;
    }

    table hula_nhop {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            hula_get_nhop;
            drop;
        }
        default_action = drop;
        size = TOR_NUM;
    }

    table dmac {
        key = {
            standard_metadata.egress_spec : exact;
        }
        actions = {
            set_dmac;
            nop;
        }
        default_action = nop;
        size = 16;
    }

    table debug2{
        key = {
            hdr.hula.qdepth: exact;
            meta.old_qdepth: exact;
        }
        actions = {
            nop;
        }
        default_action = nop;
        size = 1;
    }
    
    apply {
        if (hdr.hula.isValid()){
            if (hdr.hula.dir == 0){
                switch(hula_fwd.apply().action_run){
                    hula_dst: {
                        srcindex_qdepth_reg.read(meta.old_qdepth, meta.index);
                        if (meta.old_qdepth > hdr.hula.qdepth){
                            srcindex_qdepth_reg.write(meta.index, hdr.hula.qdepth);
                            srcindex_digest_reg.write(meta.index, hdr.hula.digest);

                            /* return the packet */
                            hdr.hula.dir = 1;
                            standard_metadata.egress_spec = standard_metadata.ingress_port;
                        }else{
                            /* update the oldpath if it has gone worse */
                            digest_t old_digest;
                            srcindex_digest_reg.read(old_digest, meta.index);
                            if (old_digest == hdr.hula.digest){
                                srcindex_qdepth_reg.write(meta.index, hdr.hula.qdepth);
                            }
                            drop();
                        } 
                        debug2.apply();
                    }
                }
            }else {
                /* update routing table */
                hula_bwd.apply();
                /* drop if source */
                hula_src.apply();
            }
            if (hdr.ipv4.isValid()){
                update_ttl();
            }
        }else if (hdr.ipv4.isValid()){
            //hash<bit<16>, bit<16>, tuple<bit<32>, bit<32>, bit<16>>, bit<32>>(
            hash(
                meta.hash, 
                HashAlgorithm.crc16, 
                16w0, 
                { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort}, 
                32w65536);
            /* look into hula tables */
            bit<16> port;
            flow_port_reg.read(port, (bit<32>)meta.hash);
            if (port == 0){
                hula_nhop.apply();
                flow_port_reg.write((bit<32>)meta.hash, (bit<16>)standard_metadata.egress_spec);
            }else{
                standard_metadata.egress_spec = (bit<9>)port;
            }
            dmac.apply();
        }else {
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action hula_max_qdepth(){
        hdr.hula.qdepth = (qdepth_t)standard_metadata.deq_qdepth;
    } 
    action nop(){}

    table debug{
        key = {
            hdr.hula.dir: exact;
            hdr.hula.qdepth: exact;
            standard_metadata.deq_qdepth: exact;
        }
        actions = {
            nop;
        }
        default_action = nop;
        size = 1;
    }

    apply {
        if (hdr.hula.isValid() && hdr.hula.dir == 0){
            if (hdr.hula.qdepth < (qdepth_t)standard_metadata.deq_qdepth){
                /* update queue length */
                hula_max_qdepth();
            }else{
            } 
            debug.apply();
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control computeChecksum(
    inout headers  hdr,
    inout metadata meta)
{
    Checksum16() ipv4_checksum;
    
    apply {
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdrChecksum = ipv4_checksum.get(
            {    
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            });
        }
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.hula);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
ParserImpl(),
verifyChecksum(),
ingress(),
egress(),
computeChecksum(),
DeparserImpl()
) main;
