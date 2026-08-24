#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/kvm.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/*
 * Podman 5.8.x hard-codes `-accel kvm -cpu host` for its Linux/amd64
 * machine provider. This native, static launcher preserves those arguments
 * when KVM is usable and substitutes QEMU's software accelerator when it is
 * not. It performs one execv call and never interprets a command string.
 */

static bool kvm_is_usable(void) {
    int descriptor = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (descriptor < 0) {
        return false;
    }
    int version = ioctl(descriptor, KVM_GET_API_VERSION, 0);
    int saved_errno = errno;
    close(descriptor);
    errno = saved_errno;
    return version == KVM_API_VERSION;
}

static int sibling_qemu_path(char output[PATH_MAX + 1]) {
    ssize_t length = readlink("/proc/self/exe", output, PATH_MAX);
    if (length <= 0 || length >= PATH_MAX) {
        return -1;
    }
    output[length] = '\0';
    static const char suffix[] = ".real";
    if ((size_t)length + sizeof(suffix) > PATH_MAX + 1) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(output + length, suffix, sizeof(suffix));
    return 0;
}

int main(int argc, char **argv) {
    if (argc <= 0 || argc > 4096) {
        fputs("managed QEMU launcher received an invalid argument count\n", stderr);
        return 126;
    }

    char qemu_path[PATH_MAX + 1];
    if (sibling_qemu_path(qemu_path) != 0) {
        perror("managed QEMU launcher could not resolve its payload");
        return 126;
    }

    char **arguments = calloc((size_t)argc + 1, sizeof(*arguments));
    if (arguments == NULL) {
        perror("managed QEMU launcher could not allocate argv");
        return 126;
    }
    arguments[0] = qemu_path;
    bool use_kvm = kvm_is_usable();
    for (int index = 1; index < argc; index++) {
        arguments[index] = argv[index];
        if (!use_kvm && index > 1 && strcmp(argv[index - 1], "-accel") == 0
                && strcmp(argv[index], "kvm") == 0) {
            arguments[index] = "tcg";
        } else if (!use_kvm && index > 1 && strcmp(argv[index - 1], "-cpu") == 0
                && strcmp(argv[index], "host") == 0) {
            arguments[index] = "max";
        }
    }
    arguments[argc] = NULL;

    execv(qemu_path, arguments);
    perror("managed QEMU launcher could not execute its verified payload");
    free(arguments);
    return 126;
}
