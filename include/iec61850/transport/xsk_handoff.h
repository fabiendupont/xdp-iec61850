/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * AF_XDP fd handoff protocol between the privileged daemon and the rootless
 * application.
 *
 * The daemon sends one message on the Unix domain socket:
 *   - iov[0]: struct xsk_handoff_msg  (UMEM geometry)
 *   - cmsg:   SCM_RIGHTS with two fds: [xsk_fd, umem_fd]
 *
 * The application calls packet_io_create_xsk_inherited() which does the
 * recvmsg and calls xgl_xsk_inherit() internally.
 */

#ifndef IEC61850_XSK_HANDOFF_H
#define IEC61850_XSK_HANDOFF_H

#include <linux/types.h>

#define XSK_HANDOFF_MAGIC  0x584B4844U  /* "XKHD" */
#define XSK_HANDOFF_FD_XSK  0
#define XSK_HANDOFF_FD_UMEM 1
#define XSK_HANDOFF_NUM_FDS 2

struct xsk_handoff_msg {
    __u32 magic;       /* XSK_HANDOFF_MAGIC — sanity check */
    __u32 frame_size;  /* UMEM frame size (typically 4096) */
    __u32 num_frames;  /* Number of UMEM frames (power of 2) */
    __u32 reserved;    /* padding — must be zero */
};

#endif /* IEC61850_XSK_HANDOFF_H */
