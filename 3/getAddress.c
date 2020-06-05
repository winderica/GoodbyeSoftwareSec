#include <libnet.h>
#include <netinet/ip_icmp.h>

struct ICMP {
    struct icmphdr header;
    char payload[64 - sizeof(struct icmphdr)];
};

uint16_t checksum(void *buf, int length) {
    uint32_t sum = 0;
    for (; length > 1; length -= 2) {
        sum += *(uint16_t *) buf++;
    }
    if (length == 1) {
        sum += *(uint8_t *) buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

int ping(uint32_t addr) {
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sd < 0) {
        return 0;
    }
    int ttl = 64;
    setsockopt(sd, SOL_IP, IP_TTL, &ttl, sizeof(ttl));
    struct timeval tv = {
        .tv_sec = 1,
        .tv_usec = 0,
    };
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr.s_addr = addr
    };

    struct ICMP packet = {0};

    packet.header.type = ICMP_ECHO;
    packet.header.un.echo.id = getpid();
    packet.header.un.echo.sequence = 0;
    for (int i = 0; i < sizeof(packet.payload) - 1; i++) {
        packet.payload[i] = i + '0';
    }
    uint32_t packetSize = sizeof(struct ICMP);
    packet.header.checksum = checksum(&packet, packetSize);

    if (sendto(sd, &packet, packetSize, 0, (struct sockaddr *) &dst, sizeof(dst)) <= 0) {
        close(sd);
        return 0;
    }

    if (recvfrom(sd, &packet, packetSize, 0, NULL, NULL) > 0) {
        if (packet.header.type == 69 && packet.header.code == 0) {
            printf("%s\n", inet_ntoa(dst.sin_addr));
            close(sd);
            return 1;
        }
    }
    close(sd);
    return 0;
}

uint32_t randomAddress() {
    uint32_t ip = rand() & 0xff;
    ip |= (rand() & 0xff) << 8;
    ip |= (rand() & 0xff) << 16;
    ip |= (rand() & 0xff) << 24;
    return ip;
}

int main(int argc, char *argv[]) {
    if (argc == 2) {
        int i = 0;
        while (i < 10) {
            if (ping(randomAddress())) {
                i++;
            }
        }
    } else if (argc == 3) {
        uint32_t ip = inet_addr(argv[1]);
        uint32_t mask = inet_addr(argv[2]);
        uint32_t start = ntohl(ip & mask);
        uint32_t end = ntohl(ip | (~mask));
        for (uint32_t i = start; i < end; i++) {
            ping(htonl(i));
        }
    } else {
        printf("Usage: %s <random_count>\n", argv[0]);
        printf("       %s <ip_address> <subnet_mask>\n", argv[0]);
    }
}
