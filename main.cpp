#include <iostream>
#include <string>
#include <netinet/ip.h>
#include <linux/netfilter.h>
#include <netinet/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

std::string block_host; // 차단할 host

// NFQUEUE에서 전달된 패킷 데이터에서 패킷 고유 ID를 추출하는 함수
u_int32_t get_packet_id(struct nfq_data* tb) {
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(tb);
    return ph ? ntohl(ph->packet_id) : 0;
}

// 패킷 데이터가 HTTP 요청인지 확인하고, 특정 호스트를 차단 대상인지 판단하는 함수
bool is_http_packet(unsigned char* data, int size) {
    struct iphdr* iph = (struct iphdr*)data;
    if (iph->protocol != IPPROTO_TCP) return false; // HTTP 판별

    int ip_header_len = iph->ihl * 4;
    struct tcphdr* tcph = (struct tcphdr*)(data + ip_header_len);
    int tcp_header_len = tcph->doff * 4;

    char* payload = (char*)(data + ip_header_len + tcp_header_len);
    int payload_len = size - ip_header_len - tcp_header_len;
    if (payload_len <= 0) return false;

    std::string http_data(payload, payload + payload_len);
    size_t host_pos = http_data.find("Host: ");
    if (host_pos != std::string::npos) {
        size_t end = http_data.find("\r\n", host_pos);
        if (end != std::string::npos) {
            std::string host = http_data.substr(host_pos + 6, end - host_pos - 6);
            if (host == block_host) {
                std::cout << "Blocked host: " << host << std::endl;
                return true;
            }
        }
    }
    return false;
}

// 각 패킷을 받아 차단 대상인지 판단 후, 해당 패킷을 DROP 또는 ACCEPT 처리
static int cb(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfa, void*) {
    u_int32_t id = get_packet_id(nfa);
    unsigned char* data;
    int len = nfq_get_payload(nfa, &data);
    if (len >= 0) {
        if (is_http_packet(data, len)) {
            return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <host>" << std::endl;
        return 1;
    }
    block_host = argv[1];

    struct nfq_handle* h = nfq_open();
    if (!h) { perror("nfq_open"); exit(1); }

    nfq_unbind_pf(h, AF_INET);
    nfq_bind_pf(h, AF_INET);

    struct nfq_q_handle* qh = nfq_create_queue(h, 0, &cb, nullptr);
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned));
    int rv;
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
