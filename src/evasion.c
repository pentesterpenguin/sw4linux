/*
    Research the specificity of how sandboxes operate.
    Then implement multiple ways of catching them.
    Even if one function chekcs the box of a sandbox,
    shutdown execution to not leave room for analysis.

    https://attack.mitre.org/techniques/T1497/
    https:///golinuxcloud.com/check-if-server-is-physical-or-virtual/

    Cannot cover all, so here are the priorities :
    1 - VM detection ✅ (sys_vendor and product_name)
    2 - Debugger detection ✅ (/proc/self/status)
    3 - Docker container detection ✅ (.dockerenv, rootfs, PID 1 - process name)

    Each functions checks the conditions, and if it's being analyzed it returns true (1);
    Might add time based analysis to find out if it's a sandbox or not. Not for now.
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/vfs.h>

#define OVERLAYFS_SUPER_MAGIC 0x794c7630

// Encrypted version of: "/sys/class/dmi/id/sys_vendor"
static const uint8_t enc_sys_vendor_path[] = {
  0x7E, 0x5E, 0xE2, 0xA8, 0x85, 0xCE, 0x2D, 0x9D, 0x5C, 0xA0, 0xEE, 0x7C, 0x49, 0xCE, 0x74, 0x63, 0xBC, 0x31, 0xE5, 0x70, 0x9D, 0x4F, 0x75, 0x0D, 0xE9, 0xE9, 0xF9, 0x98
};
static const uint8_t enc_sys_vendor_path_keys[] = {
  0x51, 0x2D, 0x9B, 0xDB, 0xAA, 0xAD, 0x41, 0xFC, 0x2F, 0xD3, 0xC1, 0x18, 0x24, 0xA7, 0x5B, 0x0A, 0xD8, 0x1E, 0x96, 0x09, 0xEE, 0x10, 0x03, 0x68, 0x87, 0x8D, 0x96, 0xEA
};

// Encrypted version of: "/sys/class/dmi/id/product_name"
static const uint8_t enc_product_name_path[] = {
  0x55, 0x10, 0x8D, 0xA6, 0x1D, 0xF9, 0x35, 0x54, 0xDA, 0xFA, 0x24, 0x21, 0x8D, 0x13, 0x56, 0xF6, 0xD8, 0x00, 0xC0, 0xBA, 0xAE, 0x1B, 0x83, 0x84, 0xC9, 0x62, 0xFF, 0xF5, 0x73, 0x21
};
static const uint8_t enc_product_name_path_keys[] = {
  0x7A, 0x63, 0xF4, 0xD5, 0x32, 0x9A, 0x59, 0x35, 0xA9, 0x89, 0x0B, 0x45, 0xE0, 0x7A, 0x79, 0x9F, 0xBC, 0x2F, 0xB0, 0xC8, 0xC1, 0x7F, 0xF6, 0xE7, 0xBD, 0x3D, 0x91, 0x94, 0x1E, 0x44
};

// Encrypted version of: "/proc/self/status"
static const uint8_t enc_proc_status_path[] = {
  0x91, 0x04, 0x1B, 0xD6, 0x68, 0xAC, 0xE3, 0xA5, 0xF3, 0x4B, 0x3D, 0x79, 0xB2, 0xF3, 0x4A, 0xA1, 0x38
};
static const uint8_t enc_proc_status_path_keys[] = {
  0xBE, 0x74, 0x69, 0xB9, 0x0B, 0x83, 0x90, 0xC0, 0x9F, 0x2D, 0x12, 0x0A, 0xC6, 0x92, 0x3E, 0xD4, 0x4B
};

// Encrypted version of: "TracerPid"
static const uint8_t enc_tracer_pid[] = {
  0xC4, 0x9B, 0xA8, 0xCD, 0x34, 0xE2, 0x4F, 0x08, 0x6D
};
static const uint8_t enc_tracer_pid_keys[] = {
  0x90, 0xE9, 0xC9, 0xAE, 0x51, 0x90, 0x1F, 0x61, 0x09
};

// Encrypted version of: "/.dockerenv"
static const uint8_t enc_dockerenv_path[] = {
  0x35, 0x63, 0x75, 0x7C, 0x29, 0xE7, 0xB1, 0x4D, 0x2E, 0x27, 0xF5
};
static const uint8_t enc_dockerenv_path_keys[] = {
  0x1A, 0x4D, 0x11, 0x13, 0x4A, 0x8C, 0xD4, 0x3F, 0x4B, 0x49, 0x83
};

// Encrypted version of: "/proc/1/comm"
static const uint8_t enc_proc_comm_path[] = {
  0x03, 0x49, 0x60, 0xE7, 0xED, 0xCE, 0xEA, 0xC4, 0x3A, 0xF5, 0x19, 0xDC
};
static const uint8_t enc_proc_comm_path_keys[] = {
  0x2C, 0x39, 0x12, 0x88, 0x8E, 0xE1, 0xDB, 0xEB, 0x59, 0x9A, 0x74, 0xB1
};

// Encrypted version of: "init"
static const uint8_t enc_init_str[] = {
  0x07, 0x88, 0x2E, 0xCD
};
static const uint8_t enc_init_str_keys[] = {
  0x6E, 0xE6, 0x47, 0xB9
};

// Encrypted version of: "systemd"
static const uint8_t enc_systemd_str[] = {
  0x5C, 0x9C, 0x00, 0x65, 0xDF, 0xA6, 0x9A
};
static const uint8_t enc_systemd_str_keys[] = {
  0x2F, 0xE5, 0x73, 0x11, 0xBA, 0xCB, 0xFE
};

// Encrypted VM vendor strings
// Encrypted version of: "VMware"
static const uint8_t enc_vm_vendor_0[] = { 0x26, 0x1E, 0xF4, 0x91, 0x29, 0xA0 };
static const uint8_t enc_vm_vendor_0_keys[] = { 0x70, 0x53, 0x83, 0xF0, 0x5B, 0xC5 };

// Encrypted version of: "innotek GmbH"
static const uint8_t enc_vm_vendor_1[] = { 0xCB, 0x2D, 0x17, 0xF5, 0x87, 0xF1, 0x93, 0x6E, 0x79, 0x04, 0xAB, 0xF3 };
static const uint8_t enc_vm_vendor_1_keys[] = { 0xA2, 0x43, 0x79, 0x9A, 0xF3, 0x94, 0xF8, 0x4E, 0x3E, 0x69, 0xC9, 0xBB };

// Encrypted version of: "Oracle Corporation"
static const uint8_t enc_vm_vendor_2[] = { 0x04, 0x5F, 0x92, 0x06, 0x87, 0x5C, 0x1B, 0x84, 0xAF, 0xE9, 0xAB, 0x95, 0x1C, 0x1A, 0x3D, 0x2B, 0xE0, 0xEC };
static const uint8_t enc_vm_vendor_2_keys[] = { 0x4B, 0x2D, 0xF3, 0x65, 0xEB, 0x39, 0x3B, 0xC7, 0xC0, 0x9B, 0xDB, 0xFA, 0x6E, 0x7B, 0x49, 0x42, 0x8F, 0x82 };

// Encrypted version of: "Microsoft Corporation"
static const uint8_t enc_vm_vendor_3[] = { 0xE7, 0xF2, 0xB9, 0x59, 0xCF, 0x52, 0x48, 0x89, 0x08, 0xA6, 0xB6, 0x52, 0x76, 0x44, 0xE2, 0x8F, 0x36, 0x85, 0xEA, 0xF3, 0xF4 };
static const uint8_t enc_vm_vendor_3_keys[] = { 0xAA, 0x9B, 0xDA, 0x2B, 0xA0, 0x21, 0x27, 0xEF, 0x7C, 0x86, 0xF5, 0x3D, 0x04, 0x34, 0x8D, 0xFD, 0x57, 0xF1, 0x83, 0x9C, 0x9A };

// Encrypted version of: "QEMU"
static const uint8_t enc_vm_vendor_4[] = { 0xE4, 0xED, 0x68, 0x41 };
static const uint8_t enc_vm_vendor_4_keys[] = { 0xB5, 0xA8, 0x25, 0x14 };

// Encrypted version of: "Xen"
static const uint8_t enc_vm_vendor_5[] = { 0x69, 0xC4, 0x2C };
static const uint8_t enc_vm_vendor_5_keys[] = { 0x31, 0xA1, 0x42 };

// Encrypted version of: "Google"
static const uint8_t enc_vm_vendor_6[] = { 0x8F, 0xBD, 0x16, 0xBC, 0x44, 0x08 };
static const uint8_t enc_vm_vendor_6_keys[] = { 0xC8, 0xD2, 0x79, 0xDB, 0x28, 0x6D };

// Encrypted version of: "Amazon EC2"
static const uint8_t enc_vm_vendor_7[] = { 0x7D, 0x98, 0x1E, 0xDB, 0xDC, 0x7E, 0x92, 0x33, 0xCB, 0x46 };
static const uint8_t enc_vm_vendor_7_keys[] = { 0x3C, 0xF5, 0x7F, 0xA1, 0xB3, 0x10, 0xB2, 0x76, 0x88, 0x74 };

// Encrypted VM product strings
// Encrypted version of: "KVM"
static const uint8_t enc_vm_product_0[] = { 0xB2, 0x01, 0xEA };
static const uint8_t enc_vm_product_0_keys[] = { 0xF9, 0x57, 0xA7 };

// Encrypted version of: "Standard PC (i440FX + PIIX, 1996)"
static const uint8_t enc_vm_product_1[] = { 0xEC, 0x79, 0xDD, 0xE2, 0x39, 0x12, 0xFA, 0x23, 0x73, 0x4D, 0x46, 0x5B, 0x5A, 0x85, 0x88, 0x2A, 0xDF, 0xB9, 0xFB, 0xF1, 0xD8, 0x9B, 0x80, 0xF0, 0xF3, 0xF8, 0xE6, 0x87, 0x26, 0xED, 0xEF, 0x35, 0xAC };
static const uint8_t enc_vm_product_1_keys[] = { 0xBF, 0x0D, 0xBC, 0x8C, 0x5D, 0x73, 0x88, 0x47, 0x53, 0x1D, 0x05, 0x7B, 0x72, 0xEC, 0xBC, 0x1E, 0xEF, 0xFF, 0xA3, 0xD1, 0xF3, 0xBB, 0xD0, 0xB9, 0xBA, 0xA0, 0xCA, 0xA7, 0x17, 0xD4, 0xD6, 0x03, 0x85 };

// Encrypted version of: "Standard PC (Q35 + ICH9, 2009)"
static const uint8_t enc_vm_product_2[] = { 0xA4, 0xE5, 0x44, 0x8B, 0xE8, 0xDB, 0x8D, 0x11, 0x21, 0xD6, 0x2F, 0x7F, 0x40, 0x07, 0xD9, 0x7A, 0x21, 0x5D, 0x19, 0xD1, 0x88, 0x84, 0xFC, 0x59, 0xFC, 0xEE, 0x15, 0xDF, 0xE7, 0xFE };
static const uint8_t enc_vm_product_2_keys[] = { 0xF7, 0x91, 0x25, 0xE5, 0x8C, 0xBA, 0xFF, 0x75, 0x01, 0x86, 0x6C, 0x5F, 0x68, 0x56, 0xEA, 0x4F, 0x01, 0x76, 0x39, 0x98, 0xCB, 0xCC, 0xC5, 0x75, 0xDC, 0xDC, 0x25, 0xEF, 0xDE, 0xD7 };

// Encrypted version of: "VirtualBox"
static const uint8_t enc_vm_product_3[] = { 0x23, 0x37, 0xEE, 0x7D, 0xD5, 0x27, 0x46, 0x8A, 0x40, 0xDB };
static const uint8_t enc_vm_product_3_keys[] = { 0x75, 0x5E, 0x9C, 0x09, 0xA0, 0x46, 0x2A, 0xC8, 0x2F, 0xA3 };

// Encrypted version of: "VMware Virtual Platform"
static const uint8_t enc_vm_product_4[] = { 0x76, 0x4B, 0xFE, 0xF9, 0x4A, 0xE5, 0x15, 0xD6, 0x5A, 0xAC, 0x24, 0x4B, 0x7B, 0xC1, 0x47, 0x7B, 0xF4, 0xD3, 0xA5, 0x04, 0x11, 0x19, 0xF7 };
static const uint8_t enc_vm_product_4_keys[] = { 0x20, 0x06, 0x89, 0x98, 0x38, 0x80, 0x35, 0x80, 0x33, 0xDE, 0x50, 0x3E, 0x1A, 0xAD, 0x67, 0x2B, 0x98, 0xB2, 0xD1, 0x62, 0x7E, 0x6B, 0x9A };

// Encrypted version of: "VMware7,1"
static const uint8_t enc_vm_product_5[] = { 0xBB, 0x0E, 0xE0, 0x96, 0x06, 0xF1, 0x1B, 0x21, 0x41 };
static const uint8_t enc_vm_product_5_keys[] = { 0xED, 0x43, 0x97, 0xF7, 0x74, 0x94, 0x2C, 0x0D, 0x70 };

// Encrypted version of: "VMware20,1"
static const uint8_t enc_vm_product_6[] = { 0x43, 0x34, 0xC9, 0xC1, 0x1A, 0x22, 0x08, 0x7D, 0xA7, 0x64 };
static const uint8_t enc_vm_product_6_keys[] = { 0x15, 0x79, 0xBE, 0xA0, 0x68, 0x47, 0x3A, 0x4D, 0x8B, 0x55 };

// Encrypted version of: "Virtual Machine"
static const uint8_t enc_vm_product_7[] = { 0x97, 0x91, 0xD8, 0x15, 0x81, 0xAF, 0xFC, 0xC2, 0x15, 0xCF, 0x9C, 0x9A, 0x71, 0x8E, 0x77 };
static const uint8_t enc_vm_product_7_keys[] = { 0xC1, 0xF8, 0xAA, 0x61, 0xF4, 0xCE, 0x90, 0xE2, 0x58, 0xAE, 0xFF, 0xF2, 0x18, 0xE0, 0x12 };

// Encrypted version of: "HVM domU"
static const uint8_t enc_vm_product_8[] = { 0x3A, 0x91, 0x01, 0x4C, 0xAF, 0x8B, 0x9D, 0x1B };
static const uint8_t enc_vm_product_8_keys[] = { 0x72, 0xC7, 0x4C, 0x6C, 0xCB, 0xE4, 0xF0, 0x4E };

// Encrypted version of: "OpenStack Nova"
static const uint8_t enc_vm_product_9[] = { 0x5F, 0xEF, 0xAC, 0x2F, 0xEA, 0xC4, 0xE5, 0xFB, 0xAF, 0x5C, 0x34, 0x89, 0x04, 0xA8 };
static const uint8_t enc_vm_product_9_keys[] = { 0x10, 0x9F, 0xC9, 0x41, 0xB9, 0xB0, 0x84, 0x98, 0xC4, 0x7C, 0x7A, 0xE6, 0x72, 0xC9 };

// Encrypted version of: "Amazon EC2"
static const uint8_t enc_vm_product_10[] = { 0x05, 0x5D, 0x6B, 0xFD, 0x07, 0xBC, 0xA2, 0xB7, 0xBF, 0x55 };
static const uint8_t enc_vm_product_10_keys[] = { 0x44, 0x30, 0x0A, 0x87, 0x68, 0xD2, 0x82, 0xF2, 0xFC, 0x67 };

// Encrypted version of: "Google Compute Engine"
static const uint8_t enc_vm_product_11[] = { 0x72, 0x3B, 0x1C, 0xE3, 0x62, 0xE6, 0x42, 0x49, 0xF4, 0x6E, 0xCB, 0x54, 0x5E, 0x18, 0x50, 0xF0, 0xC8, 0xB4, 0x82, 0x48, 0xDA };
static const uint8_t enc_vm_product_11_keys[] = { 0x35, 0x54, 0x73, 0x84, 0x0E, 0x83, 0x62, 0x0A, 0x9B, 0x03, 0xBB, 0x21, 0x2A, 0x7D, 0x70, 0xB5, 0xA6, 0xD3, 0xEB, 0x26, 0xBF };

static char decrypt_buf[256];

static char* decrypt_string(const uint8_t *encrypted, const uint8_t *keys, size_t len) {
    for (size_t i = 0; i < len; i++) {
        decrypt_buf[i] = encrypted[i] ^ keys[i];
    }
    decrypt_buf[len] = '\0';
    return decrypt_buf;
}

// check /sys/class/dmi/id/sys_vendor
int check_sys_vendor() {
    FILE* fptr;
    // Encrypted version of: "/sys/class/dmi/id/sys_vendor"
    char *path = decrypt_string(enc_sys_vendor_path, enc_sys_vendor_path_keys, sizeof(enc_sys_vendor_path));
    fptr = fopen(path, "r");
    if (fptr == NULL) return 0;

    char vendor_name[50];
    fgets(vendor_name, sizeof(vendor_name), fptr);

    struct {
        const uint8_t *enc;
        const uint8_t *keys;
        size_t len;
    } vm_vendors[] = {
        {enc_vm_vendor_0, enc_vm_vendor_0_keys, sizeof(enc_vm_vendor_0)},
        {enc_vm_vendor_1, enc_vm_vendor_1_keys, sizeof(enc_vm_vendor_1)},
        {enc_vm_vendor_2, enc_vm_vendor_2_keys, sizeof(enc_vm_vendor_2)},
        {enc_vm_vendor_3, enc_vm_vendor_3_keys, sizeof(enc_vm_vendor_3)},
        {enc_vm_vendor_4, enc_vm_vendor_4_keys, sizeof(enc_vm_vendor_4)},
        {enc_vm_vendor_5, enc_vm_vendor_5_keys, sizeof(enc_vm_vendor_5)},
        {enc_vm_vendor_6, enc_vm_vendor_6_keys, sizeof(enc_vm_vendor_6)},
        {enc_vm_vendor_7, enc_vm_vendor_7_keys, sizeof(enc_vm_vendor_7)},
        {NULL, NULL, 0}
    };

    for (int i = 0; vm_vendors[i].enc != NULL; i++) {
        char *vendor_str = decrypt_string(vm_vendors[i].enc, vm_vendors[i].keys, vm_vendors[i].len);
        if (strstr(vendor_name, vendor_str) != NULL) {
            fclose(fptr);
            return 1;
        }
    }

    fclose(fptr);
    return 0;
}

// check /sys/class/dmi/id/product_name
int check_product_name() {
    FILE* fptr;
    // Encrypted version of: "/sys/class/dmi/id/product_name"
    char *path = decrypt_string(enc_product_name_path, enc_product_name_path_keys, sizeof(enc_product_name_path));
    fptr = fopen(path, "r");
    if (fptr == NULL) return 0;

    char target_vm_product[50];
    fgets(target_vm_product, sizeof(target_vm_product), fptr);

    struct {
        const uint8_t *enc;
        const uint8_t *keys;
        size_t len;
    } vm_products[] = {
        {enc_vm_product_0, enc_vm_product_0_keys, sizeof(enc_vm_product_0)},
        {enc_vm_product_1, enc_vm_product_1_keys, sizeof(enc_vm_product_1)},
        {enc_vm_product_2, enc_vm_product_2_keys, sizeof(enc_vm_product_2)},
        {enc_vm_product_3, enc_vm_product_3_keys, sizeof(enc_vm_product_3)},
        {enc_vm_product_4, enc_vm_product_4_keys, sizeof(enc_vm_product_4)},
        {enc_vm_product_5, enc_vm_product_5_keys, sizeof(enc_vm_product_5)},
        {enc_vm_product_6, enc_vm_product_6_keys, sizeof(enc_vm_product_6)},
        {enc_vm_product_7, enc_vm_product_7_keys, sizeof(enc_vm_product_7)},
        {enc_vm_product_8, enc_vm_product_8_keys, sizeof(enc_vm_product_8)},
        {enc_vm_product_9, enc_vm_product_9_keys, sizeof(enc_vm_product_9)},
        {enc_vm_product_10, enc_vm_product_10_keys, sizeof(enc_vm_product_10)},
        {enc_vm_product_11, enc_vm_product_11_keys, sizeof(enc_vm_product_11)},
        {NULL, NULL, 0}
    };

    for (int i = 0; vm_products[i].enc != NULL; i++) {
        char *product_str = decrypt_string(vm_products[i].enc, vm_products[i].keys, vm_products[i].len);
        if (strstr(target_vm_product, product_str) != NULL) {
            fclose(fptr);
            return 1;
        }
    }

    fclose(fptr);
    return 0;
}

// detect if it's been tracked with /proc/self/status
/* If it's not being traced the TracerPid is 0.
In the contrary it's the PID of the tracer. So we stop execution. */
int check_debugger_self_status(){
    FILE* fptr;
    // Encrypted version of: "/proc/self/status"
    char *path = decrypt_string(enc_proc_status_path, enc_proc_status_path_keys, sizeof(enc_proc_status_path));
    fptr = fopen(path, "r");
    if (fptr == NULL) return 0;

    char currentLine[100];
    while(fgets(currentLine, 100, fptr))
    {
        // Encrypted version of: "TracerPid"
        char *tracer_str = decrypt_string(enc_tracer_pid, enc_tracer_pid_keys, sizeof(enc_tracer_pid));
        if(strstr(currentLine, tracer_str) != NULL) {
            // cursor is moved by 10 bytes to get the PID
            int tracker_id = atoi(currentLine+10);
            if (tracker_id != 0) {
                fclose(fptr);
                return 1;
            }
        }
    }

    fclose(fptr);
    return 0;
}

int check_if_in_container() {
    // check if .dockerenv is present in root directory
    // Encrypted version of: "/.dockerenv"
    char *dockerenv = decrypt_string(enc_dockerenv_path, enc_dockerenv_path_keys, sizeof(enc_dockerenv_path));
    if (access(dockerenv, F_OK) == 0) {
        return 1;
    }

    // check if /proc/mounts shows overlay for rootfs
    // file parsing is more fragile so I use the statfs syscall
    struct statfs fs;
    if (statfs("/", &fs) == 0 && fs.f_type == OVERLAYFS_SUPER_MAGIC) {
        return 1;
    }

    // check if PID 1 is systemd or init
    // process name is saved in /proc/PID/comm (max 16 bytes)
    char process_name[16];
    FILE* fptr;
    // Encrypted version of: "/proc/1/comm"
    char *comm_path = decrypt_string(enc_proc_comm_path, enc_proc_comm_path_keys, sizeof(enc_proc_comm_path));
    fptr = fopen(comm_path, "r");
    if (fptr == NULL) return 0;
    fgets(process_name, 16, fptr);
    process_name[strcspn(process_name, "\n")] = 0;

    // Encrypted version of: "init"
    char *init_str = decrypt_string(enc_init_str, enc_init_str_keys, sizeof(enc_init_str));
    if (strcmp(process_name, init_str) == 0) {
        fclose(fptr);
        return 0;  // Normal SysV init
    }

    // Encrypted version of: "systemd"
    char *systemd_str = decrypt_string(enc_systemd_str, enc_systemd_str_keys, sizeof(enc_systemd_str));
    if (strcmp(process_name, systemd_str) == 0) {
        fclose(fptr);
        return 0;  // Normal systemd
    }

    fclose(fptr);
    return 1;  // Unknown PID 1 = likely container
}
