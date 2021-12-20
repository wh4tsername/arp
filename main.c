#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define conditional_handle_error(stmt, msg) \
  do {                                      \
    if (stmt) {                             \
      perror(msg " (" #stmt ")");           \
      exit(EXIT_FAILURE);                   \
    }                                       \
  } while (0)

#define IP_LEN 4
#define IP_STR_LEN 16
#define MAC_LEN 6

typedef struct {
  uint8_t tha[MAC_LEN];
  uint8_t sha[MAC_LEN];
  uint16_t proto;
} __attribute__((__packed__)) eth_header;

typedef struct {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t operation;
  uint8_t sha[MAC_LEN];
  uint8_t spa[IP_LEN];
  uint8_t tha[MAC_LEN];
  uint8_t tpa[IP_LEN];
} __attribute__((__packed__)) arp_header;

typedef struct {
  eth_header eth;
  arp_header arp;
} __attribute__((__packed__)) arp_package;

typedef struct {
  char s[3 * 6];
} mac_str;

mac_str mac_to_str(u_char* mac) {
  mac_str mac_str;
  sprintf(mac_str.s, "%02x:%02x:%02x:%02x:%02x:%02x", (int)mac[0], (int)mac[1],
          (int)mac[2], (int)mac[3], (int)mac[4], (int)mac[5]);
  return mac_str;
}

uint8_t char_to_dig(char ch) { return ch - '0'; }

typedef union {
  in_addr_t addr;
  uint8_t bytes[IP_LEN];
} ip_struct;

ip_struct str_to_ip(char* str) {
  ip_struct ip_struct;
  ip_struct.addr = 0;
  size_t str_len = strlen(str);
  size_t j = 0;
  for (size_t i = 0; i < str_len; ++i) {
    if (str[i] == '.') {
      ++j;
      continue;
    }
    ip_struct.bytes[j] = ip_struct.bytes[j] * 10 + char_to_dig(str[i]);
  }

  return ip_struct;
}

void form_request(arp_package* request, uint8_t* smac, uint8_t* sip,
                  struct in_addr tip) {
  request->arp.htype = htons(1);
  request->arp.ptype = htons(ETH_P_IP);
  request->arp.hlen = MAC_LEN;
  request->arp.plen = IP_LEN;
  request->arp.operation = htons(1);

  memset(request->arp.tha, 0, MAC_LEN);
  memcpy(request->arp.tpa, &tip, IP_LEN);
  memcpy(request->arp.sha, smac, MAC_LEN);
  memcpy(request->arp.spa, sip, IP_LEN);

  request->eth.proto = htons(ETH_P_ARP);
  memset(request->eth.tha, 0xFF, MAC_LEN);
  memcpy(request->eth.sha, smac, MAC_LEN);
}

int main(int argc, char** argv) {
  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  conditional_handle_error(sock == -1, "socket error");

  struct ifreq ifr;
  strcpy((char*)&ifr.ifr_name, argv[1]);

  conditional_handle_error(ioctl(sock, SIOCGIFHWADDR, &ifr) == -1,
                           "can't get mac");
  uint8_t smac[MAC_LEN];
  char mac_str[3 * MAC_LEN];
  memcpy(smac, ifr.ifr_hwaddr.sa_data, MAC_LEN);
  strcpy(mac_str, mac_to_str(smac).s);

  conditional_handle_error(ioctl(sock, SIOCGIFADDR, &ifr) == -1,
                           "can't get ip");
  uint8_t sip[IP_LEN];
  memcpy(sip, ifr.ifr_hwaddr.sa_data, IP_LEN);

  conditional_handle_error(ioctl(sock, SIOCGIFINDEX, &ifr) == -1,
                           "can't get index");

  struct sockaddr_ll device = {.sll_family = PF_PACKET,
                               .sll_protocol = htons(ETH_P_IP),
                               .sll_ifindex = ifr.ifr_ifindex,
                               .sll_hatype = 1,
                               .sll_pkttype = PACKET_HOST,
                               .sll_halen = 0};

  uint8_t tip_str[IP_STR_LEN];
  while (scanf("%s", tip_str) != EOF) {
    struct in_addr tip;
    tip.s_addr = str_to_ip((char*)tip_str).addr;

    arp_package package;
    form_request(&package, smac, sip, tip);

    conditional_handle_error(
        sendto(sock, &package, sizeof(arp_package), 0,
               (struct sockaddr*)&device, sizeof(device)) == -1,
        "can't send");

    do {
      conditional_handle_error(
          recv(sock, &package, sizeof(arp_package), 0) == -1, "can't recv");
    } while (strcmp(mac_str, mac_to_str(package.eth.tha).s) != 0);

    printf("%s\n", mac_to_str(package.arp.sha).s);
  }

  close(sock);

  return 0;
}
