#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach-o/loader.h>

#define BUFFER_SIZE 2048

#define LOGMSG(...) printf(__VA_ARGS__)

#define KERNEL_BASE (0x1000000 + 0xFFFFFFF007004000)

pid_t gKernelPID = 0;
task_t gKernelTask;
uint8_t *gBuffer = NULL;

static int readall(int sockfd, void *outbuf, size_t len)
{
    size_t bytesread = 0;
    while (bytesread < len) {
        ssize_t res = recv(sockfd, outbuf + bytesread, len - bytesread, 0);
        if (res <= 0) {
            LOGMSG("[-] error: recv() failed: %s\n", strerror(errno));
            return -1;
        }
        bytesread += res;
    }
    return 0;
}

int handle_read(int clientfd)
{
    size_t remaining = 0;
    size_t offset = 0;
    kern_return_t res = 0;
    vm_size_t readsize = 0;
    ssize_t sent = 0;
    struct read_args
    {
        uint64_t address;
        uint32_t length;
    } __attribute__((packed)) args;

    if (readall(clientfd, &args, sizeof(struct read_args)) == -1) {
        LOGMSG("[-] error: readall() failed\n");
        return -1;
    }

    remaining = args.length;
    while(remaining > 0) {
        size_t toread = remaining > 2048 ? 2048 : remaining;
        res = vm_read_overwrite(gKernelTask, (vm_address_t)(args.address+offset), toread, (vm_address_t)gBuffer, &readsize);
        if (res != KERN_SUCCESS || readsize != toread) {
            LOGMSG("[-] error: failed to read %u bytes from 0x%llx\n", args.length, args.address);
            return -1;
        }
        remaining -= toread;
        offset += toread;

        sent = send(clientfd, gBuffer, toread, 0);
        if (sent <= 0) {
            LOGMSG("[-] error: send() failed: %s\n", strerror(errno));
            return -1;
        }
    }
    return 0;
}

int handle_write(int clientfd)
{
    size_t remaining = 0;
    size_t offset = 0;
    kern_return_t res = 0;
    struct write_args
    {
        uint64_t address;
        uint32_t length;
    } __attribute__((packed)) args;

    if (readall(clientfd, &args, sizeof(struct write_args)) == -1) {
        LOGMSG("[-] error: readall() failed\n");
        return -1;
    }

    remaining = args.length;
    while (remaining > 0) {
        uint32_t towrite = remaining > 2048 ? 2048 : remaining;
        if (readall(clientfd, gBuffer, towrite) < 0) {
            LOGMSG("[-] error: readall() failed.\n");
            return -1;
        }

        res = vm_write(gKernelTask, (vm_address_t)(args.address + offset), (vm_address_t)gBuffer, towrite);
        if (res != KERN_SUCCESS) {
            LOGMSG("[-] error: failed to write %u bytes to 0x%llx\n", args.length, args.address);
            return -1;
        }
        remaining -= towrite;
        offset += towrite;
    }

    return 0;
}

static int send_hello(int clientfd, uint64_t kernelbase, uint64_t kaslr)
{
    ssize_t sent = 0;
    struct hello_args {
        uint64_t kernelbase;
        uint64_t kaslr;
    } __attribute__((packed)) args;

    args.kernelbase = kernelbase;
    args.kaslr = kaslr;
    sent = send(clientfd, &args, sizeof(struct hello_args), 0);
    if (sent != sizeof(struct hello_args)) {
        LOGMSG("[-] error: send() failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static uint64_t get_kernel_base()
{
    vm_address_t address;
    uint64_t kernelbase = 0;
    vm_address_t testbase = 0;
    vm_size_t size;
    kern_return_t res;
    int i;
    char buffer[4096];
    struct mach_header_64 *mh = (struct mach_header_64 *)&buffer;

    address = KERNEL_BASE;
    memset(buffer, 0, sizeof(buffer));
    for(i = 256; i > 0; i--) {
        testbase = address + 0x200000*i;
        res = vm_read_overwrite(gKernelTask, testbase, sizeof(struct mach_header_64), (vm_address_t)&buffer, &size);
        if (res != KERN_SUCCESS)
            continue;

        if (mh->magic != MH_MAGIC && mh->magic != MH_MAGIC_64)
            continue;
        if (mh->cputype != CPU_TYPE_ARM && mh->cputype != CPU_TYPE_ARM64) {
            continue;
        }
        if (mh->filetype != MH_EXECUTE || (mh->flags != 0x200001)) {
            continue;
        }
        if (mh->sizeofcmds > 4095)
            continue;
        kernelbase = testbase;
        break;
    }
    return kernelbase;
}

int main(int argc, char *argv[])
{
    uint16_t lport = 31337;
    int sockfd = -1;
    int clientfd = -1;
    int opt = 1;
    int c;
    struct sockaddr_in saddr;
    int saddr_len = sizeof(saddr);
    ssize_t datasent = 0;
    int retval = EXIT_SUCCESS;
    int running = 1;
    int daemon = 0;
    uint64_t kernelbase = 0;
    kern_return_t res;

    if (getuid() != 0) {
        printf("[-] error: need to run as root\n");
        return EXIT_FAILURE;
    }

    printf("[+] running as root\n");
    while ((c = getopt(argc, argv, "p:d")) != -1) {
        switch (c) {
            case 'p':
            {
                int v = atoi(optarg);
                if (v < 0 || v > 65535) {
                    LOGMSG("[-] error: invalid port number\n");
                    return EXIT_FAILURE;
                }
                lport = (uint16_t)v;
            }
            break;
            case '?':
            default:
                LOGMSG("[-] error:  invalid arguments\n");
                return EXIT_FAILURE;
        }
    }

    res = task_for_pid(mach_task_self(), gKernelPID, &gKernelTask);
    if (res != KERN_SUCCESS) {
        res = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &gKernelTask);
    }
    if (res != KERN_SUCCESS) {
        LOGMSG("[-] error: cannot get kernel task\n");
        return EXIT_FAILURE;
    }
    LOGMSG("[+] got kernel task\n");

    kernelbase = get_kernel_base();
    if (kernelbase == 0) {
        LOGMSG("[-] error: could not determine kernel base\n");
        return EXIT_FAILURE;
    }
    LOGMSG("[+] got kernel base: 0x%llx\n", kernelbase);

    gBuffer = malloc(BUFFER_SIZE);
    if (gBuffer == NULL) {
        LOGMSG("[-] error: could not allocate working buffer\n");
        return EXIT_FAILURE;
    }
    LOGMSG("[+] Binding to local port %d\n", lport);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        LOGMSG("[-] error: socket() failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        LOGMSG("[-] error: setsockopt() 1 failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
        LOGMSG("[-] error: setsockopt() 2 failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(lport);

    if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        LOGMSG("[-] error: bind() failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (listen(sockfd, 1) == -1) {
        LOGMSG("[-] error: listen() failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    
    while (running) {
        char cmd = 0;
        ssize_t bytesread = 0;
        if (clientfd == -1) {
            ssize_t sent = 0;
            clientfd = accept(sockfd, (struct sockaddr *)&saddr, (socklen_t *)&saddr_len);
            if (clientfd == -1) {
                LOGMSG("[-] error: accept() failed: %s\n", strerror(errno));
                return EXIT_FAILURE;
            }
            LOGMSG("[+] client connected\n");
            // send hello: kernel_base
            if (send_hello(clientfd, kernelbase, kernelbase - KERNEL_BASE) == -1) {
                LOGMSG("[-] error: send_hello() failed.\n");
                return EXIT_FAILURE;
            }
            LOGMSG("[+] kernel base and kaslr sent to client\n");
        }

        // wait for command
        bytesread = recv(clientfd, &cmd, sizeof(cmd), 0);
        if (bytesread <= 0) {
            LOGMSG("[-] error: recv() failed: %s\n", strerror(errno));
            close(clientfd);
            clientfd = -1;
            cmd = 0;
        }

        switch(cmd) {
            case 'r':
            {
                LOGMSG("[+] read command received\n");
                if (handle_read(clientfd) == -1) {
                    LOGMSG("[-] error: handle_read() failed\n");
                    close(clientfd);
                    clientfd = -1;
                }
            }
            break;

            case 'w':
            {
                LOGMSG("[+] write command received\n");
                if (handle_write(clientfd) == -1) {
                    LOGMSG("[-] error: handle_write() failed\n");
                    close(clientfd);
                    clientfd = -1;
                }
            }
            break;

            case 'd':
            {
                LOGMSG("[+] client disconnected\n");
                close(clientfd);
                clientfd = -1;
            }
            break;

            case 'q':
            {
                LOGMSG("[+] quit command received\n");
                running = 0;
            }
            break;
        }
    }

    if (clientfd != -1)
        close(clientfd);
    if (sockfd != -1)
        close(sockfd);
    if (gBuffer != NULL)
        free(gBuffer);

    LOGMSG("[+] shutting down...\n");
    return retval;
}