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
	struct TxPacket *txpkt = new TxPacket;
	struct RxPacket *rxpkt = new RxPacket;
	const uint8_t* packet;
	struct pcap_pkthdr *header;
        uint32_t send_ip;
	uint64_t send_session_id;
	uint32_t send_mpid;
	uint8_t plus_seq = 0x100;		

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
		rxpkt -> openvpnudphdr = (struct OpenVpnUdpHdr* )(packet + ETH_SIZE + rxpkt->iphdr->ipHdrSize()+UDP_SIZE);
                if(rxpkt->openvpnudphdr->type() == OpenVpnUdpHdr::P_CONTROL_HARD_RESET_CLIENT_V2){
			send_ip = rxpkt -> iphdr->src_;
			send_session_id = rxpkt -> openvpnudphdr->sessionid_;
			continue;
		}
		if(rxpkt->openvpnudphdr->type() == OpenVpnUdpHdr::P_CONTROL_V1 || rxpkt->openvpnudphdr->type() == OpenVpnUdpHdr::P_ACK_V1){
			if(rxpkt->iphdr->src_ == send_ip){
				send_mpid = rxpkt -> openvpnudphdr->mpid() + plus_seq;
				plus_seq += 0x100;
			}
			continue;
		}
		if(rxpkt->openvpnudphdr->type() != OpenVpnUdpHdr::P_DATA_V2){
			printf("not detect data_v2\n");
			continue;
		}
		//printf("this is DATA_V2\n");	
		
		memcpy(&(txpkt->ethhdr), rxpkt->ethhdr, ETH_SIZE);
                memcpy(&(txpkt->iphdr), rxpkt->iphdr, 20);
                txpkt->iphdr.id_ = 0x4444;
                txpkt->iphdr.hdrLen_ = 5;
		txpkt->iphdr.checksum_ = IpHdr::calcIpChecksum(&(txpkt->iphdr));
                memcpy(&(txpkt->udphdr), rxpkt->udphdr, UDP_SIZE);
		txpkt->udphdr.checksum_ = UdpHdr::calcUdpChecksum(&(txpkt->iphdr), &(txpkt->udphdr));
                memcpy(&(txpkt->openvpnudphdr), rxpkt->openvpnudphdr, rxpkt->udphdr->payloadLen());
                //txpkt->iphdr.src_ = send_ip;
                txpkt->openvpnudphdr.type_ = OpenVpnUdpHdr::P_CONTROL_V1;
		txpkt->openvpnudphdr.sessionid_ = send_session_id;
                txpkt->openvpnudphdr.mpidarraylength_ = 0;
		txpkt->openvpnudphdr.mpid_ = ntohl(send_mpid);
		printf("mpid = %u to %d\n ", rxpkt->openvpnudphdr->mpid(), send_mpid);
		//printf("%d",send_mpid);

		/*
		for(int ix=0;ix<1000;ix++){
			res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(txpkt), 14+20+8+txpkt->udphdr.payloadLen());
 			printf("print something! \n");
			usleep(100000);
			}
		*/
		
	  res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(txpkt), 14+20+8+txpkt->udphdr.payloadLen());
          if(res !=0){
                  printf("%s",errbuf);
          } else {

	  	printf("======%d======\n", pktCnt);
		printf("this is DATA_V2\n");
		//printf("mpid = %d to %d\n", rxpkt->openvpnudphdr->mpidarraylength_, send_mpid);
	  }
	}
	
	delete txpkt;
	delete rxpkt;
	pcap_close(pcap);
	return 0;
}
