#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_macaddress(const u_int8_t *ether_host) {
	for (int i = 0; i < ETHER_ADDR_LEN - 1; i++) {
		printf("%02x:", ether_host[i]);
	}
	printf("%02x\n", ether_host[ETHER_ADDR_LEN]);
}

void packet_capture(struct pcap_pkthdr* header, const u_char* packet) {
	const struct libnet_ethernet_hdr *ethernet = (struct libnet_ethernet_hdr*)(packet);
	if (ntohs(ethernet->ether_type) != ETHERTYPE_IP) return;

	const struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
	if (ip->ip_p != IPPROTO_TCP) return;

	size_t size_ip = ip->ip_hl*4;
	if (size_ip < 20) {
		//printf("\n* Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	const struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr*)(packet + LIBNET_ETH_H + size_ip);
	size_t size_tcp = tcp->th_off*4;
	if (size_tcp < 20) {
		//printf("\n* Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	const u_char *payload = (u_char *)(packet + LIBNET_ETH_H + size_ip + size_tcp);
	size_t size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	if (size_payload == 0) return;

	printf("Ethernet dst mac: ");
	print_macaddress(ethernet->ether_dhost);
	printf("Ethernet src mac: ");
	print_macaddress(ethernet->ether_shost);

	printf("  src ip: %s\n", inet_ntoa(ip->ip_src));
	printf("  dst ip: %s\n", inet_ntoa(ip->ip_dst));
	printf("  src port: %d\n", ntohs(tcp->th_sport));
	printf("  dst port: %d\n", ntohs(tcp->th_dport));

	const u_char *ch = payload;
	printf("  Payload: ");

	for (size_t i = 0; i < size_payload; i++) {
		printf("0x%02x ", *ch);
		ch++;
		if (i == 19) {
			printf("\n");
			break;
		}
	}

	return;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		packet_capture(header, packet);
	}

	pcap_close(pcap);
}
