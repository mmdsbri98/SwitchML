/* -*- P4_16 -*- */

// CS5229 Programming Assignment 2
// Part B - Switch ML
//
// Name: Albert Einstein
// Student Number: A0123456B
// NetID: e0123456

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  IPV4_UDP_PRON = 0x11;
const bit<16> SWITCHML_UDP_PORT = 0x3824;
const bit<32> SWITCH_ML_CAPACITY = 8;
const bit<32> SWITCH_ML_HOST_NUM = 4;

const bit<32> SWITCH_IP = 0x0a0000FE;


enum bit<16> SWITCHML_OPT {
    DROPOFF = 0x0101,
    RECORDED = 0xFFFF,
    FAILURE = 0x0000,
    RESULT = 0x1234
}

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> Valuable_Size;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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

header icmp_t {
    /* TODO: your code here */
    /* Hint: define ICMP header */
}

header udp_t {
    /* TODO: your code here */
    /* Hint: define UDP header */
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> checksum;
}

header switchml_t {
      bit<16> hostID;
      bit<16> opCode;
      bit<32> val0;
      bit<32> val1;
      bit<32> val2;
      bit<32> val3;
      bit<32> val4;
      bit<32> val5;
      bit<32> val6;
      bit<32> val7;
}

struct metadata {
      bit<1> drop;
      bit<3> hot_counts;
      bit<1> done_aggregation;
      bit<1> f_forward;
      bit<1> invalidOpcode;
      bit<1> tcpFlag;
      bit<1> wrongIp;
    /* Do you need any meta data? */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    icmp_t       icmp;
    switchml_t   switch_ml;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
        	TYPE_IPV4: parse_ipv4;
        	default: accept;
        }
    }
    state parse_ipv4 {
	    packet.extract(hdr.ipv4);
	    transition select(hdr.ipv4.protocol) {
        	17: parse_udp;
        	1: parse_icmp;
        	6: set_drop_flag;
        	default: accept;
        }
	
    }
    state parse_udp {
	    packet.extract(hdr.udp);
	    transition select(hdr.udp.dport) {
        	SWITCHML_UDP_PORT: parse_switchml;		
        	default: set_drop_flag;
        }
	
    }
    state parse_switchml {
	   packet.extract(hdr.switch_ml);
	   transition accept;
	
    }
    state parse_icmp {
	    packet.extract(hdr.icmp);
	    transition accept;
	
    }
    state set_drop_flag {
    	//meta.drop = 1;
    	meta.tcpFlag = 1;
    	transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* TODO: Define your registers */
    /* TODO: Define your action functions */
    register<bit<32>>(8) current_val;
   
    register<bit<2>>(4) recieved_val;
    
    register<bit<8>>(1) count;
    
    action aggregation(Valuable_Size val0, Valuable_Size val1, Valuable_Size val2,
                       Valuable_Size val3, Valuable_Size val4, Valuable_Size val5, 
                       Valuable_Size val6, Valuable_Size val7) {
    	
    	Valuable_Size val0_reg;
    	current_val.read(val0_reg,0);
    	bit<32> myval0 = val0_reg + val0;
    	current_val.write(0, myval0);
    	
    	Valuable_Size val1_reg;
    	current_val.read(val1_reg,1);
    	bit<32> myval1 = val1_reg + val1;
    	current_val.write(1, myval1);
    	
    	Valuable_Size val2_reg;
    	current_val.read(val2_reg,2);
    	bit<32> myval2 = val2_reg + val2;
    	current_val.write(2, myval2);
    	
    	Valuable_Size val3_reg;
    	current_val.read(val3_reg,3);
    	bit<32> myval3 = val3_reg + val3;
    	current_val.write(3, myval3);
    	
    	Valuable_Size val4_reg;
    	current_val.read(val4_reg,4);
    	bit<32> myval4 = val4_reg + val4;
    	current_val.write(4, myval4);
    	
    	Valuable_Size val5_reg;
    	current_val.read(val5_reg,5);
    	bit<32> myval5 = val5_reg + val5;
    	current_val.write(5, myval5);
    	
    	Valuable_Size val6_reg;
    	current_val.read(val6_reg,6);
    	bit<32> myval6 = val6_reg + val6;
    	current_val.write(6, myval6);
    	
    	Valuable_Size val7_reg;
    	current_val.read(val7_reg,7);
    	bit<32> myval7 = val7_reg + val7;
    	current_val.write(7, myval7);
    	
    	bit <8> count_now;
    	count.read(count_now, 0);
    	count.write(0,count_now+1);
    	
    	bit <8> aggregations;
    	count.read(aggregations, 0);
    	
    	if (aggregations == 4) {
    		meta.done_aggregation = 1;
    		
    	}
    }
    
    action create_packetresult() {
        bit<32> finalVal0;
        bit<32> finalVal1;
        bit<32> finalVal2;
        bit<32> finalVal3;
        bit<32> finalVal4;
        bit<32> finalVal5;
        bit<32> finalVal6;
        bit<32> finalVal7;
        
        current_val.read(finalVal0,0);
        hdr.switch_ml.val0 = finalVal0;
        current_val.write(0,0);
        
        current_val.read(finalVal1,1);
        hdr.switch_ml.val1 = finalVal1;
        current_val.write(1,0);
        
        current_val.read(finalVal2,2);
        hdr.switch_ml.val2 = finalVal2;
        current_val.write(2,0);
        
        current_val.read(finalVal3,3);
        hdr.switch_ml.val3 = finalVal3;
        current_val.write(3,0);
        
        current_val.read(finalVal4,4);
        hdr.switch_ml.val4 = finalVal4;
        current_val.write(4,0);
        
        current_val.read(finalVal5,5);
        hdr.switch_ml.val5 = finalVal5;
        current_val.write(5,0);
        
        current_val.read(finalVal6,6);
        hdr.switch_ml.val6 = finalVal6;
        current_val.write(6,0);
        
        current_val.read(finalVal7,7);
        hdr.switch_ml.val7 = finalVal7;
        current_val.write(7,0);
        
        hdr.switch_ml.opCode = 0x1234;
    }
    
 
    action ipv4_forward_action(egressSpec_t port) {     
            standard_metadata.egress_spec = port;
    }
    
    action multicast() {
        standard_metadata.mcast_grp = 1;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }
    

    table ipv4_forward {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward_action;
            multicast;
            drop;
        }
        default_action = multicast();
    }
    

    apply {
        
        if (hdr.ethernet.isValid() && hdr.ipv4.isValid()) {
            if (hdr.udp.isValid() && hdr.udp.dport == SWITCHML_UDP_PORT && hdr.ipv4.dstAddr != SWITCH_IP) {
                meta.wrongIp =1;
                //hdr.switch_ml.opCode = SWITCHML_OPT.FAILURE;
                //meta.drop = 1;
                //drop();
            }
            
            if (hdr.udp.dport != SWITCHML_UDP_PORT && hdr.switch_ml.isValid() && hdr.ipv4.dstAddr == SWITCH_IP){ 
                meta.drop = 1;
                drop();
            }
            
            
            if (hdr.ipv4.dstAddr == SWITCH_IP && meta.tcpFlag == 1) {
                meta.drop = 1;
                drop();
            }
            
            if (hdr.switch_ml.isValid() && hdr.switch_ml.opCode == SWITCHML_OPT.DROPOFF && hdr.ipv4.dstAddr == SWITCH_IP)  {
                //    
            }else if (hdr.switch_ml.isValid() && hdr.ipv4.dstAddr == SWITCH_IP){
                meta.invalidOpcode = 1;
                hdr.switch_ml.opCode = 0x0000;
            }
            
            if (meta.drop == 1) {
                drop();
            }
            
            if (hdr.switch_ml.isValid() && hdr.switch_ml.opCode == 0x0101 && hdr.ipv4.dstAddr == SWITCH_IP) {
                bit<2> temp_var;
                bit<32> host_id;
                host_id = (bit<32>) hdr.switch_ml.hostID;
            	recieved_val.read(temp_var,host_id);
            	if (temp_var != 3) {
            	    aggregation(hdr.switch_ml.val0,hdr.switch_ml.val1,hdr.switch_ml.val2,hdr.switch_ml.val3,hdr.switch_ml.val4,hdr.switch_ml.val5,hdr.switch_ml.val6,hdr.switch_ml.val7);
            	     recieved_val.write(host_id,3);
            	}
            	hdr.switch_ml.opCode =  0xFFFF;
               meta.f_forward = 1;
    	       
            }
            
            if (meta.done_aggregation == 1) {
                
    		 count.write(0,0);
    		 recieved_val.write(0,0);
    		 recieved_val.write(1,0);
    		 recieved_val.write(2,0);
    		 recieved_val.write(3,0);
                meta.done_aggregation = 0;
                create_packetresult();
                multicast();
            	
            }
            
            /* TODO: your code here */
            /* Hint 1: verify if the secret message is destined to the switch */
            /* Hint 2: there are two cases to handle -- DROPOFF, PICKUP */
            /* Hint 3: what happens when you PICKUP from an empty mailbox? */
            /* Hint 4: remember to "sanitize" your mailbox with 0xdeadbeef after every PICKUP */
            /* Hint 5: msg_checksums are important! */
            /* Hint 6: once everything is done, swap addresses, set port and reply to sender */
            //if (hdr.ethernet.dstAddr != SWITCH_IP){
            //if (hdr.udp.dport != SWITCHML_UDP_PORT || hdr.udp.sport != SWITCHML_UDP_PORT) {
                //drop();
            //}else{
                //ipv4_forward.apply();
            //}
            if (meta.drop != 1) {
                 ipv4_forward.apply();
            }
            
            //}
        } else {
            // Not IPv4 packet
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_host(macAddr_t eth_addr, ip4Addr_t ip_addr, bit<16> host_id) {
        /* TODO: your code here */
        if (meta.f_forward == 1 || meta.invalidOpcode == 1){
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = eth_addr;
            hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
            hdr.ipv4.dstAddr = ip_addr;
            hdr.switch_ml.hostID = host_id;
        }else{
            //
        }
    }

    table port_to_host {
        key = {
            standard_metadata.egress_port : exact;
        }
        actions = {
            set_host;
            drop;
        }
        size = 1024;
        default_action = drop;
    }
    

    apply {
        /* TODO: your codes here */
        /* HINT: update destination information */
        /* HINT: check the runtime table, there will something you need*/
        port_to_host.apply();
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
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
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
         packet.emit(hdr.ethernet);
         packet.emit(hdr.ipv4);
         packet.emit(hdr.udp);
         packet.emit(hdr.switch_ml);
         //packet.emit(hdr.icmp);
        /* TODO: your code here */
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
