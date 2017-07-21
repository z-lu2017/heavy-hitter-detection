/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SRCROUTING = 0x1234;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header srcRoute_t {
    bit<1>    bos;
    bit<15>   port;
}

header srcRoutingTail_t {
    bit<16>   etherType;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    srcRoute_t   srcRoute;
    srcRoutingTail_t srcRoutingTail;
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
            TYPE_SRCROUTING: parse_srcRouting;
            default: accept;
        }
    }

    state parse_srcRouting {
        packet.extract(hdr.srcRoute);
        transition select(hdr.srcRoute.bos) {
            1: parse_srcRoutingTail;
            default: accept;
        }
    }

    state parse_srcRoutingTail {
        packet.extract(hdr.srcRoutingTail);
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
    
    action srcRoute_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoute.port;
       // hdr.srcRoute.setInValid();
    }

    action srcRoute_finish() {
        hdr.ethernet.etherType = hdr.srcRoutingTail.etherType;
        //hdr.srcRoutingTail.setInValid();
    }
    
    apply {
        if (hdr.srcRoute.isValid()){
            if (hdr.srcRoute.bos == 1){
                srcRoute_finish();
            }
            srcRoute_nhop();
        }else{
            drop();
        } 
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control computeChecksum(
    inout headers  hdr,
    inout metadata meta)
{
    apply {  }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
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
