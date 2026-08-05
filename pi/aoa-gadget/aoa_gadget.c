/*
 * aoa_gadget — minimal AOA (Android Open Accessory) device-side handshake
 * over a Linux FunctionFS gadget, for the 9CarPlay Phase 2 live test.
 *
 * ROLE DIRECTION (confirmed against the public AOA spec, not the informal
 * phrasing in the top-level CLAUDE.md — see README.md "Correction"):
 *   - The head unit is the USB HOST and the AOA "accessory" role.
 *   - This program makes the Pi the USB DEVICE and the AOA "device" role —
 *     the same role a real Android phone plays when docked.
 *   - GetProtocol (51) is a device-to-host (IN) control transfer: WE report
 *     our supported protocol version to the head unit.
 *   - SendString (52) is host-to-device (OUT): the HEAD UNIT sends us its
 *     identity strings (manufacturer/model/description/version/uri/serial —
 *     this is where "manufacturer=RealVNC" etc, found in vncbearer-USBAAP.dll
 *     during firmware analysis, actually gets sent FROM). We just receive and
 *     log them — there is no matching/filtering to do, since we aren't a
 *     stock Android OS picking an app to launch.
 *   - Start (53) tells us to switch to accessory data mode; from then on the
 *     bulk endpoints carry whatever byte stream the accessory bearer speaks
 *     (expected to be the RFB stream, per PROTOCOL_ANALYSIS.md).
 *
 * This program only implements enough to observe that stream, not to speak
 * RFB back — that's the next milestone once we've confirmed how far the
 * handshake gets. Everything received after Start is hex-dumped to stdout
 * and appended to a raw capture file for offline analysis alongside a
 * parallel `usbmon` capture.
 *
 * Build: gcc -O2 -Wall -o aoa_gadget aoa_gadget.c
 * Run (after setup_gadget.sh has created the gadget, BEFORE binding the UDC):
 *   ./aoa_gadget /dev/ffs-aoa0
 *
 * UNTESTED ON REAL HARDWARE — written and reviewed against the public
 * FunctionFS/AOA specs (linux/usb/functionfs.h, source.android.com AOA2 doc)
 * but there was no Linux/Pi box available in the dev environment that
 * produced this to compile or run it against a real dwc2 UDC. Treat this as
 * a first draft to validate on the Pi, not as verified-working code.
 */

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

/* ---- FunctionFS / USB descriptor structures (uapi/linux/usb/functionfs.h,
 * uapi/linux/usb/ch9.h) reproduced here so this file has no build-time
 * dependency on kernel headers being present/matching on the build host. */

#define FUNCTIONFS_DESCRIPTORS_MAGIC_V2 3u
#define FUNCTIONFS_STRINGS_MAGIC        2u

#define FUNCTIONFS_HAS_FS_DESC 1u
#define FUNCTIONFS_HAS_HS_DESC 2u

/* usb_functionfs_event.type values */
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

static const char *aoa_string_names[6] = {
    "manufacturer", "model", "description", "version", "uri", "serial",
};

/* ---- Descriptor + strings blob written to ep0 before the UDC is bound.
 * One bulk OUT (host->device, "sink" for us) and one bulk IN (device->host,
 * "source") endpoint — this is the pipe the accessory byte stream (expected
 * to be RFB, per PROTOCOL_ANALYSIS.md) will use after AOA_START. */

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
    .fs_count = 3, /* interface + 2 endpoints */
    .hs_count = 3,
    .fs_descs = {
        .intf = {
            .bLength = sizeof(struct usb_interface_descriptor),
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = 0xFF,    /* vendor-specific, matches AOA accessory ifc */
            .bInterfaceSubClass = 0xFF,
            .bInterfaceProtocol = 0xFF,
            .iInterface = 1,
        },
        .sink = {
            .bLength = sizeof(struct usb_endpoint_descriptor_no_audio),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 1 | USB_DIR_OUT,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = 64, /* full-speed */
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
            .wMaxPacketSize = 512, /* high-speed */
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
        .code = 0x0409, /* US English */
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

static void handle_setup(int ep0, const struct usb_ctrlrequest *req) {
    int is_in = (req->bRequestType & USB_DIR_IN) != 0;
    int is_vendor = ((req->bRequestType >> 5) & 0x3) == 2;

    printf("[setup] bRequestType=0x%02x bRequest=%u wValue=%u wIndex=%u wLength=%u\n",
           req->bRequestType, req->bRequest, req->wValue, req->wIndex, req->wLength);

    if (!is_vendor) {
        /* Not an AOA request — let the kernel/host proceed with whatever
         * standard handling applies; nothing for us to do on ep0 here. */
        return;
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
        printf("  -> AOA_START received. Head unit expects us to now behave as\n"
               "     the accessory data pipe. Identity strings received:\n");
        for (int i = 0; i < 6; i++) {
            printf("       %-14s = \"%s\"\n", aoa_string_names[i], aoa_strings[i]);
        }
        printf("  -> Switching to bulk capture mode on ep1/ep2.\n");
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
}

static void ep0_event_loop(int ep0) {
    struct usb_functionfs_event events[4];
    ssize_t n = read(ep0, events, sizeof(events));
    if (n < 0) {
        if (errno == EAGAIN) return;
        perror("read(ep0)");
        return;
    }
    size_t count = n / sizeof(struct usb_functionfs_event);
    static const char *names[] = {
        "BIND", "UNBIND", "ENABLE", "DISABLE", "SETUP", "SUSPEND", "RESUME",
    };
    for (size_t i = 0; i < count; i++) {
        struct usb_functionfs_event *ev = &events[i];
        if (ev->type <= FUNCTIONFS_RESUME) {
            printf("[event] %s\n", names[ev->type]);
        }
        if (ev->type == FUNCTIONFS_SETUP) {
            handle_setup(ep0, &ev->u.setup);
        } else if (ev->type == FUNCTIONFS_ENABLE) {
            printf("[event] gadget ENABLEd by host — enumeration complete\n");
        }
    }
}

/* Dump whatever bytes show up on the bulk OUT endpoint. Previously this only
 * ran after seeing AOA_START on ep0 — but if the head unit treats a device
 * already presenting at the AOA accessory VID/PID (0x18d1/0x2d00, see
 * "Known simplifications" in README.md) as already-switched, it may skip
 * GetProtocol/SendString/Start entirely and write straight to the bulk
 * endpoint. This is now read concurrently with ep0 via poll() in main(), not
 * gated on any control-transfer state, so that case is observable too. */
static void handle_bulk_data(const uint8_t *buf, ssize_t n) {
    time_t now = time(NULL);
    printf("[%ld] received %zd bytes from head unit on bulk OUT (no AOA_START required to see this):\n",
           (long)now, n);
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
    (void)ep_in; /* unused until we start speaking RFB back */

    printf("Descriptors written and all endpoints opened.\n");
    printf("Now bind the UDC in another shell to start enumeration:\n");
    printf("  echo <udc-name> > /sys/kernel/config/usb_gadget/aoa0/UDC\n\n");

    capture_fp = fopen("aoa_capture.bin", "ab");
    if (!capture_fp) perror("fopen aoa_capture.bin (continuing without file capture)");

    printf("Watching ep0 (control/AOA events) and ep1 (bulk OUT) concurrently —\n"
           "bulk data no longer requires AOA_START to be observed. Ctrl-C to stop.\n");

    /* Only poll ep0 — FunctionFS implements a real .poll callback for it, so
     * POLLIN reliably means an event is waiting. The bulk endpoint files
     * (ep1/ep2) do NOT implement .poll in most kernels; a fd with no .poll
     * handler is reported by the kernel as always-ready by default, which
     * previously caused read(ep_out) — a blocking-mode fd — to block forever
     * on a false-positive readiness signal, hiding even the local ep0 BIND
     * event. ep_out is opened O_NONBLOCK above instead, and we just attempt
     * a non-blocking read of it every loop iteration regardless of what
     * poll() (which isn't even asked about it now) would have said. */
    struct pollfd fds[1];
    fds[0].fd = ep0;
    fds[0].events = POLLIN;

    uint8_t bulk_buf[16384];
    for (;;) {
        int ready = poll(fds, 1, 500 /* ms — periodic, so the ep_out check below still runs */);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        if (ready > 0 && (fds[0].revents & POLLIN)) {
            ep0_event_loop(ep0);
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
