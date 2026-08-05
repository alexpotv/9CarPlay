/*
 * aoa_gadget_twostage — AOA (Android Open Accessory) device-side handshake
 * that performs the real two-stage identity switch a phone does, instead of
 * aoa_gadget.c's shortcut of presenting at the AOA accessory VID/PID
 * (0x18d1/0x2d00) from the very first enumeration.
 *
 * WHY THIS EXISTS: a live test against the actual CR-V head unit using
 * aoa_gadget.c completed full standard USB enumeration (BIND, ENABLE) but
 * the head unit never sent any AOA control request (GetProtocol/SendString/
 * Start) and never wrote to the bulk endpoint either — it just silently
 * treated us as an uninteresting generic device. The leading theory (see
 * aoa_gadget.c's README "Known simplifications", now believed confirmed):
 * the head unit's discovery layer only recognizes a device as "its"
 * accessory session by having witnessed the actual generic-ID -> Google-ID
 * switch itself. A device that skips straight to the post-switch identity
 * is neither a discovery candidate (not at a generic ID) nor a recognized
 * accessory (never went through the handshake).
 *
 * SEQUENCE THIS PROGRAM IMPLEMENTS:
 *   1. Enumerate under a generic, non-Google placeholder VID/PID (see
 *      GENERIC_VID/GENERIC_PID below) — set by setup_gadget_twostage.sh,
 *      NOT setup_gadget.sh (which hardcodes the AOA identity directly; do
 *      not mix the two setup scripts with this binary).
 *   2. Respond to GetProtocol (51) with our supported AOA version.
 *   3. Receive and log SendString (52) calls — the head unit sends its
 *      identity strings here (manufacturer/model/etc, expected to include
 *      "RealVNC" per PROTOCOL_ANALYSIS.md).
 *   4. On Start (53): unbind the UDC, rewrite idVendor/idProduct in configfs
 *      to the AOA accessory identity (0x18d1/0x2d00), and rebind the UDC —
 *      reproducing the detach/re-enumerate a real phone does. The same
 *      FunctionFS interface/endpoint descriptors stay in effect throughout;
 *      only the device-descriptor-level VID/PID actually changes, since
 *      that's a configfs-gadget-level attribute independent of the
 *      FunctionFS descriptors written to ep0.
 *   5. After the switch, resume watching both ep0 (for any further control
 *      traffic) and the bulk endpoint (for RFB traffic) concurrently, same
 *      as aoa_gadget.c's fixed polling loop.
 *
 * UNTESTED ON REAL HARDWARE as of writing — the UDC unbind/rewrite/rebind
 * sequence in perform_switch() is a reasonable-best-effort reproduction of
 * what a real Android phone's kernel driver does internally, but has not
 * been validated against a live dwc2 controller or the actual head unit.
 * Treat this as the next draft to validate and iterate on, same spirit as
 * aoa_gadget.c originally was.
 *
 * Build: gcc -O2 -Wall -Wextra -o aoa_gadget_twostage aoa_gadget_twostage.c
 * Run (after setup_gadget_twostage.sh has created the gadget, BEFORE binding
 * the UDC):
 *   sudo ./aoa_gadget_twostage /dev/ffs-aoa0
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

/* ---- FunctionFS / USB descriptor structures — identical layout to
 * aoa_gadget.c; duplicated here (not shared via a header) so the two
 * programs stay independently readable and the proven-working fallback in
 * aoa_gadget.c is never at risk of being disturbed by twostage-only changes. */

#define FUNCTIONFS_DESCRIPTORS_MAGIC_V2 3u
#define FUNCTIONFS_STRINGS_MAGIC        2u

#define FUNCTIONFS_HAS_FS_DESC 1u
#define FUNCTIONFS_HAS_HS_DESC 2u

enum {
    FUNCTIONFS_BIND,
    FUNCTIONFS_UNBIND,
    FUNCTIONFS_ENABLE,
    FUNCTIONFS_DISABLE,
    FUNCTIONFS_SETUP,
    FUNCTIONFS_SUSPEND,
    FUNCTIONFS_RESUME,
};

struct usb_ctrlrequest {
    uint8_t  bRequestType;
    uint8_t  bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
} __attribute__((packed));

struct usb_functionfs_event {
    union {
        struct usb_ctrlrequest setup;
        uint8_t                raw[8];
    } u;
    uint8_t type;
    uint8_t _pad[3];
} __attribute__((packed));

struct usb_functionfs_descs_head_v2 {
    uint32_t magic;
    uint32_t length;
    uint32_t flags;
} __attribute__((packed));

struct usb_interface_descriptor {
    uint8_t  bLength;
    uint8_t  bDescriptorType;
    uint8_t  bInterfaceNumber;
    uint8_t  bAlternateSetting;
    uint8_t  bNumEndpoints;
    uint8_t  bInterfaceClass;
    uint8_t  bInterfaceSubClass;
    uint8_t  bInterfaceProtocol;
    uint8_t  iInterface;
} __attribute__((packed));

struct usb_endpoint_descriptor_no_audio {
    uint8_t  bLength;
    uint8_t  bDescriptorType;
    uint8_t  bEndpointAddress;
    uint8_t  bmAttributes;
    uint16_t wMaxPacketSize;
    uint8_t  bInterval;
} __attribute__((packed));

struct usb_functionfs_strings_head {
    uint32_t magic;
    uint32_t length;
    uint32_t str_count;
    uint32_t lang_count;
} __attribute__((packed));

#define USB_DT_INTERFACE 0x04
#define USB_DT_ENDPOINT  0x05
#define USB_ENDPOINT_XFER_BULK 0x02
#define USB_DIR_IN  0x80
#define USB_DIR_OUT 0x00

/* ---- AOA protocol constants (source.android.com/docs/core/interaction/accessories/aoa2) */

#define AOA_GET_PROTOCOL         51
#define AOA_SEND_STRING          52
#define AOA_START                53
#define AOA_REGISTER_HID         54
#define AOA_UNREGISTER_HID       55
#define AOA_SET_HID_REPORT_DESC  56
#define AOA_SEND_HID_EVENT       57
#define AOA_AUDIO                58

#define AOA_PROTOCOL_VERSION 2 /* AOAv2 */

/* ---- Gadget identity constants.
 *
 * GENERIC_*: the placeholder identity we enumerate under BEFORE the switch.
 * This is arbitrary — real Android phones present their own native
 * (non-Google) identity here, which we don't know for this scaffold, so
 * 0x1d6b/0x0104 (Linux Foundation "Multifunction Composite Gadget", a
 * common generic Linux gadget identity) is used as a plausible stand-in.
 * If the head unit's discovery logic turns out to filter on the *specific*
 * generic identity (not just "some non-Google ID"), this is the first thing
 * to revisit.
 *
 * ACCESSORY_*: Google's fixed AOA accessory identity — not configurable,
 * this is what AOA-aware hosts are watching for after Start.
 */
#define GENERIC_VID     "0x1d6b"
#define GENERIC_PID     "0x0104"
#define ACCESSORY_VID   "0x18d1"
#define ACCESSORY_PID   "0x2d00"

#define GADGET_DIR "/sys/kernel/config/usb_gadget/aoa0"

static const char *aoa_string_names[6] = {
    "manufacturer", "model", "description", "version", "uri", "serial",
};

/* ---- Descriptor + strings blob written to ep0 before the UDC is bound.
 * Same interface/endpoint layout throughout both stages — only the
 * device-descriptor-level VID/PID (a configfs attribute, independent of
 * these FunctionFS descriptors) changes at the switch. */

struct descriptors_v2 {
    struct usb_functionfs_descs_head_v2 header;
    uint32_t fs_count;
    uint32_t hs_count;
    struct {
        struct usb_interface_descriptor intf;
        struct usb_endpoint_descriptor_no_audio sink;   /* OUT, host->device */
        struct usb_endpoint_descriptor_no_audio source; /* IN,  device->host */
    } __attribute__((packed)) fs_descs, hs_descs;
} __attribute__((packed));

static const struct descriptors_v2 descriptors = {
    .header = {
        .magic  = FUNCTIONFS_DESCRIPTORS_MAGIC_V2,
        .length = sizeof(struct descriptors_v2),
        .flags  = FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC,
    },
    .fs_count = 3,
    .hs_count = 3,
    .fs_descs = {
        .intf = {
            .bLength = sizeof(struct usb_interface_descriptor),
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = 0xFF,
            .bInterfaceSubClass = 0xFF,
            .bInterfaceProtocol = 0xFF,
            .iInterface = 1,
        },
        .sink = {
            .bLength = sizeof(struct usb_endpoint_descriptor_no_audio),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 1 | USB_DIR_OUT,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = 64,
        },
        .source = {
            .bLength = sizeof(struct usb_endpoint_descriptor_no_audio),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 2 | USB_DIR_IN,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = 64,
        },
    },
    .hs_descs = {
        .intf = {
            .bLength = sizeof(struct usb_interface_descriptor),
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = 0xFF,
            .bInterfaceSubClass = 0xFF,
            .bInterfaceProtocol = 0xFF,
            .iInterface = 1,
        },
        .sink = {
            .bLength = sizeof(struct usb_endpoint_descriptor_no_audio),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 1 | USB_DIR_OUT,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = 512,
        },
        .source = {
            .bLength = sizeof(struct usb_endpoint_descriptor_no_audio),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 2 | USB_DIR_IN,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = 512,
        },
    },
};

#define IFACE_STRING "9CarPlay AOA bridge"

struct strings_block {
    struct usb_functionfs_strings_head header;
    struct {
        uint16_t code;
        char str1[sizeof(IFACE_STRING)];
    } __attribute__((packed)) lang0;
} __attribute__((packed));

static const struct strings_block strings = {
    .header = {
        .magic = FUNCTIONFS_STRINGS_MAGIC,
        .length = sizeof(struct strings_block),
        .str_count = 1,
        .lang_count = 1,
    },
    .lang0 = {
        .code = 0x0409,
        .str1 = IFACE_STRING,
    },
};

/* ---- runtime state ---- */

static char aoa_strings[6][256];
static FILE *capture_fp;

static void hexdump(const uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i += 16) {
        printf("  %04zx: ", i);
        for (size_t j = i; j < i + 16 && j < n; j++) printf("%02x ", buf[j]);
        printf("\n");
    }
}

/* Write `value` to a configfs/sysfs attribute file at `path`. Used for the
 * UDC bind/unbind file and idVendor/idProduct during the switch. */
static int write_attr(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
        return -1;
    }
    size_t len = strlen(value);
    ssize_t w = write(fd, value, len);
    close(fd);
    if (w != (ssize_t)len) {
        fprintf(stderr, "write(%s, \"%s\"): %s\n", path, value, strerror(errno));
        return -1;
    }
    return 0;
}

/* Find the bound UDC's name by reading the first entry in /sys/class/udc.
 * Assumes exactly one UDC on the system, same assumption the manual
 * `ls /sys/class/udc` step has made throughout this project so far. */
static int find_udc_name(char *out, size_t out_sz) {
    DIR *d = opendir("/sys/class/udc");
    if (!d) { perror("opendir(/sys/class/udc)"); return -1; }
    struct dirent *ent;
    int found = 0;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        snprintf(out, out_sz, "%s", ent->d_name);
        found = 1;
        break;
    }
    closedir(d);
    if (!found) {
        fprintf(stderr, "no UDC found in /sys/class/udc\n");
        return -1;
    }
    return 0;
}

/* The actual generic-identity -> accessory-identity switch, performed on
 * receiving AOA_START. Unbinds the UDC (soft-disconnect), rewrites
 * idVendor/idProduct to Google's AOA accessory identity, then rebinds
 * (soft-reconnect) — the host should observe this as the device
 * disappearing and a new device (now at 0x18d1/0x2d00) appearing, same as
 * it would for a real phone's post-Start re-enumeration. */
static int perform_switch(void) {
    char udc_name[256];

    printf("[switch] unbinding UDC...\n");
    if (write_attr(GADGET_DIR "/UDC", "\n") != 0) {
        fprintf(stderr, "[switch] failed to unbind UDC — aborting switch\n");
        return -1;
    }

    /* Give the host a moment to register the disconnect before we change
     * identity underneath it. Not verified against real hardware timing —
     * revisit this delay if the head unit seems confused by the switch. */
    usleep(300 * 1000);

    printf("[switch] rewriting identity to accessory VID/PID (%s/%s)...\n",
           ACCESSORY_VID, ACCESSORY_PID);
    if (write_attr(GADGET_DIR "/idVendor", ACCESSORY_VID) != 0 ||
        write_attr(GADGET_DIR "/idProduct", ACCESSORY_PID) != 0) {
        fprintf(stderr, "[switch] failed to rewrite identity — aborting switch\n");
        return -1;
    }

    if (find_udc_name(udc_name, sizeof(udc_name)) != 0) {
        fprintf(stderr, "[switch] failed to find UDC to rebind — aborting switch\n");
        return -1;
    }

    printf("[switch] rebinding UDC (%s)...\n", udc_name);
    if (write_attr(GADGET_DIR "/UDC", udc_name) != 0) {
        fprintf(stderr, "[switch] failed to rebind UDC — aborting switch\n");
        return -1;
    }

    printf("[switch] done. Now presenting as %s/%s — watching for re-enumeration.\n",
           ACCESSORY_VID, ACCESSORY_PID);
    return 0;
}

static int handle_setup(int ep0, const struct usb_ctrlrequest *req) {
    int is_in = (req->bRequestType & USB_DIR_IN) != 0;
    int is_vendor = ((req->bRequestType >> 5) & 0x3) == 2;
    int start_received = 0;

    printf("[setup] bRequestType=0x%02x bRequest=%u wValue=%u wIndex=%u wLength=%u\n",
           req->bRequestType, req->bRequest, req->wValue, req->wIndex, req->wLength);

    if (!is_vendor) {
        return 0;
    }

    switch (req->bRequest) {
    case AOA_GET_PROTOCOL: {
        uint16_t version = AOA_PROTOCOL_VERSION;
        if (is_in) {
            ssize_t w = write(ep0, &version, sizeof(version));
            printf("  -> replied GetProtocol = %u (wrote %zd bytes)\n", version, w);
        }
        break;
    }
    case AOA_SEND_STRING: {
        if (!is_in && req->wLength > 0 && req->wIndex < 6) {
            char buf[256] = {0};
            size_t want = req->wLength < sizeof(buf) - 1 ? req->wLength : sizeof(buf) - 1;
            ssize_t r = read(ep0, buf, want);
            if (r > 0) {
                buf[r] = '\0';
                snprintf(aoa_strings[req->wIndex], sizeof(aoa_strings[req->wIndex]), "%s", buf);
                printf("  -> host sent %s = \"%s\"\n", aoa_string_names[req->wIndex], buf);
            }
        }
        break;
    }
    case AOA_START: {
        printf("  -> AOA_START received. Identity strings received so far:\n");
        for (int i = 0; i < 6; i++) {
            printf("       %-14s = \"%s\"\n", aoa_string_names[i], aoa_strings[i]);
        }
        printf("  -> Performing generic -> accessory identity switch now.\n");
        start_received = 1;
        break;
    }
    case AOA_REGISTER_HID:
    case AOA_UNREGISTER_HID:
    case AOA_SET_HID_REPORT_DESC:
    case AOA_SEND_HID_EVENT:
    case AOA_AUDIO:
        printf("  -> unhandled AOA request %u (HID/audio) — not implemented in this scaffold\n",
               req->bRequest);
        break;
    default:
        printf("  -> unrecognized vendor request %u — not implemented\n", req->bRequest);
        break;
    }
    return start_received;
}

/* Returns 1 if AOA_START was seen this call (caller should trigger the
 * identity switch), 0 otherwise. */
static int ep0_event_loop(int ep0) {
    struct usb_functionfs_event events[4];
    ssize_t n = read(ep0, events, sizeof(events));
    if (n < 0) {
        if (errno == EAGAIN) return 0;
        perror("read(ep0)");
        return 0;
    }
    size_t count = n / sizeof(struct usb_functionfs_event);
    static const char *names[] = {
        "BIND", "UNBIND", "ENABLE", "DISABLE", "SETUP", "SUSPEND", "RESUME",
    };
    int start_received = 0;
    for (size_t i = 0; i < count; i++) {
        struct usb_functionfs_event *ev = &events[i];
        if (ev->type <= FUNCTIONFS_RESUME) {
            printf("[event] %s\n", names[ev->type]);
        }
        if (ev->type == FUNCTIONFS_SETUP) {
            if (handle_setup(ep0, &ev->u.setup)) {
                start_received = 1;
            }
        } else if (ev->type == FUNCTIONFS_ENABLE) {
            printf("[event] gadget ENABLEd by host — enumeration complete\n");
        }
    }
    return start_received;
}

/* Same rationale as aoa_gadget.c's fixed poll loop: ep1 (bulk OUT) doesn't
 * reliably implement .poll in FunctionFS, so it's opened O_NONBLOCK and
 * read every iteration instead of being trusted via poll() readiness. */
static void handle_bulk_data(const uint8_t *buf, ssize_t n) {
    time_t now = time(NULL);
    printf("[%ld] received %zd bytes from head unit on bulk OUT:\n", (long)now, n);
    hexdump(buf, (size_t)n);
    if (capture_fp) {
        fwrite(buf, 1, (size_t)n, capture_fp);
        fflush(capture_fp);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <ffs-mountpoint>   (e.g. /dev/ffs-aoa0)\n", argv[0]);
        return 1;
    }
    char path[512];

    snprintf(path, sizeof(path), "%s/ep0", argv[1]);
    int ep0 = open(path, O_RDWR);
    if (ep0 < 0) { perror("open ep0"); return 1; }

    ssize_t w = write(ep0, &descriptors, sizeof(descriptors));
    if (w != (ssize_t)sizeof(descriptors)) { perror("write descriptors"); return 1; }
    printf("wrote %zd bytes of descriptors to ep0\n", w);

    w = write(ep0, &strings, sizeof(strings));
    if (w != (ssize_t)sizeof(strings)) { perror("write strings"); return 1; }
    printf("wrote %zd bytes of strings to ep0\n", w);

    snprintf(path, sizeof(path), "%s/ep1", argv[1]);
    int ep_out = open(path, O_RDONLY | O_NONBLOCK);
    if (ep_out < 0) { perror("open ep1 (bulk OUT)"); return 1; }

    snprintf(path, sizeof(path), "%s/ep2", argv[1]);
    int ep_in = open(path, O_WRONLY);
    if (ep_in < 0) { perror("open ep2 (bulk IN)"); return 1; }
    (void)ep_in;

    printf("Descriptors written and all endpoints opened.\n");
    printf("Currently configured to enumerate at the GENERIC identity\n"
           "(%s/%s) — confirm setup_gadget_twostage.sh (NOT setup_gadget.sh)\n"
           "was used to create this gadget, or this program's switch step\n"
           "will have nothing meaningful to transition from.\n",
           GENERIC_VID, GENERIC_PID);
    printf("Now bind the UDC in another shell to start enumeration:\n");
    printf("  echo <udc-name> | sudo tee %s/UDC\n\n", GADGET_DIR);

    capture_fp = fopen("aoa_capture.bin", "ab");
    if (!capture_fp) perror("fopen aoa_capture.bin (continuing without file capture)");

    printf("Watching ep0 and ep1 concurrently. On AOA_START, will unbind,\n"
           "switch to the accessory identity, and rebind automatically.\n"
           "Ctrl-C to stop.\n");

    struct pollfd fds[1];
    fds[0].fd = ep0;
    fds[0].events = POLLIN;

    uint8_t bulk_buf[16384];
    for (;;) {
        int ready = poll(fds, 1, 500);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        if (ready > 0 && (fds[0].revents & POLLIN)) {
            if (ep0_event_loop(ep0)) {
                if (perform_switch() != 0) {
                    fprintf(stderr, "identity switch failed — see errors above. "
                                     "Gadget may now be in an inconsistent state; "
                                     "recommend a full teardown (see README) before retrying.\n");
                }
            }
        }

        ssize_t n = read(ep_out, bulk_buf, sizeof(bulk_buf));
        if (n > 0) {
            handle_bulk_data(bulk_buf, n);
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            perror("read(ep_out)");
        }

        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            fprintf(stderr, "ep0 closed/error, exiting\n");
            break;
        }
    }

    if (capture_fp) fclose(capture_fp);
    close(ep0);
    close(ep_out);
    close(ep_in);
    return 0;
}
