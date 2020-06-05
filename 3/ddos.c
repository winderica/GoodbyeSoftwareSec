#include <libnet.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>

#define MAX_PAYLOAD_SIZE 65535 - sizeof(struct icmphdr) - sizeof(struct ip)

uint32_t payloadSize = 64000;
uint32_t interval = 100000;
int flag = 1;

struct ICMP {
    struct icmphdr header;
    char payload[MAX_PAYLOAD_SIZE];
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

void *ping(void *addr) {
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sd < 0) {
        return NULL;
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
        .sin_addr.s_addr = inet_addr(addr)
    };

    struct timespec start, end;

    int seq = 0;
    while (flag) {
        struct ICMP packet = {0};

        packet.header.type = ICMP_ECHO;
        packet.header.un.echo.id = getpid();
        packet.header.un.echo.sequence = seq++;
        for (int i = 0; i < payloadSize - 1; i++) {
            packet.payload[i] = i + '0';
        }
        uint32_t packetSize = payloadSize + sizeof(struct icmphdr);
        packet.header.checksum = checksum(&packet, packetSize);

        usleep(interval);

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (sendto(sd, &packet, packetSize, 0, (struct sockaddr *) &dst, sizeof(dst)) <= 0) {
            continue;
        }

        if (recvfrom(sd, &packet, packetSize, 0, NULL, NULL) > 0 || seq <= 1) {
            clock_gettime(CLOCK_MONOTONIC, &end);

            if (packet.header.type == 69 && packet.header.code == 0) {
                printf(
                    "%d bytes from %s: icmp_seq=%d ttl=%d time=%f ms\n",
                    payloadSize,
                    addr,
                    seq,
                    ttl,
                    (double) (end.tv_nsec - start.tv_nsec) / 1000000 + (double) (end.tv_sec - start.tv_sec) * 1000
                );
            }
        } else {
            printf("Timeout: icmp_seq=%d\n", seq);
        }
    }
    close(sd);
    return NULL;
}

void signalHandler() {
    flag = 0;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <address> <threads_number> <payload_size> <interval>\n", argv[0]);
        return 0;
    }
    pthread_t tid;
    payloadSize = atoi(argv[3]);
    if (payloadSize > MAX_PAYLOAD_SIZE) {
        printf("Payload too large\n");
        return 0;
    }
    interval = atoi(argv[4]);
    if (interval < 100000) {
        printf("Interval too short\n");
        return 0;
    }
    signal(SIGINT, signalHandler);

    for (int i = 0; i < atoi(argv[2]); i++) {
        pthread_create(&tid, NULL, ping, argv[1]);
    }

    pthread_exit(NULL);
}
