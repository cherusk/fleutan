#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# Copyright (C) 2017  Matthias Tafelmeier
#
# flow_interceptor.py is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# flow_interceptor.py is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from bcc import BPF
import time
from socket import inet_ntop, AF_INET, AF_INET6
import ctypes as ct
from struct import pack
import functools as ft


bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>

#define RX 1
#define TX 2

struct ipv4_data_t {
    int cpu;
    u16 qu_idx;
    unsigned int dat_len;
    u64 saddr;
    u64 daddr;
    u64 lport;
    u64 dport;
    char prot[32];
};

struct ipv6_data_t {
    int cpu;
    u16 qu_idx;
    unsigned int dat_len;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 lport;
    u64 dport;
    char prot[32];
};

BPF_PERF_OUTPUT(ipv4_flows_rx);
BPF_PERF_OUTPUT(ipv4_flows_tx);
BPF_PERF_OUTPUT(ipv6_flows_rx);
BPF_PERF_OUTPUT(ipv6_flows_tx);

static int trace_skb(struct pt_regs *ctx, struct sk_buff *skb, int direction)
{
    u64 zero = 0;
    struct sk_buff *_skb = NULL;
    bpf_probe_read(&_skb, sizeof(_skb), &skb);
    struct sock *skp = NULL;
    bpf_probe_read(&skp, sizeof(skp), &_skb->sk);
    u16 _qu_idx = skb->queue_mapping;
    int curr_cpu = bpf_get_smp_processor_id();
    unsigned int dat_len = 0;

    // get flow details
    u16 family = 0, lport = 0, dport = 0;
    struct proto *prot_ref = NULL;
    bpf_probe_read(&family, sizeof(family), &skp->__sk_common.skc_family);
    bpf_probe_read(&lport, sizeof(lport), &skp->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
    bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
    bpf_probe_read(&prot_ref, sizeof(prot_ref), &skp->__sk_common.skc_prot);

    if (family == AF_INET) {
        struct ipv4_data_t data4 = { .cpu = curr_cpu, .qu_idx = _qu_idx };
        data4.lport = lport;
        data4.dport = ntohs(dport);
        bpf_probe_read(&data4.prot, sizeof(data4.prot),
            &prot_ref->name);
        bpf_probe_read(&data4.saddr, sizeof(u32),
            &skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data4.daddr, sizeof(u32),
            &skp->__sk_common.skc_daddr);
        bpf_probe_read(&data4.dat_len,
            sizeof(unsigned int), &_skb->len);
        if (direction == RX)
            ipv4_flows_rx.perf_submit(ctx, &data4, sizeof(data4));
        else
            ipv4_flows_tx.perf_submit(ctx, &data4, sizeof(data4));
    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = { .cpu = curr_cpu, .qu_idx = _qu_idx };
        data6.lport = lport;
        data6.dport = ntohs(dport);
        bpf_probe_read(&data6.prot, sizeof(data6.prot),
            &prot_ref->name);
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.dat_len,
            sizeof(unsigned int), &_skb->len);
        if (direction == RX)
            ipv6_flows_rx.perf_submit(ctx, &data6, sizeof(data6));
        else
            ipv6_flows_tx.perf_submit(ctx, &data6, sizeof(data6));
    }
    // drop other


    return 0;
}

int trace_rx_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    trace_skb(ctx, skb, RX);
    return 0;
}

int trace_tx_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    trace_skb(ctx, skb, TX);
    return 0;
}
"""

# entry data
class Data_ipv4(ct.Structure):
    _fields_ = [
        ("cpu", ct.c_int),
        ("qu_idx", ct.c_ushort),
        ("data_len", ct.c_uint),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("lport", ct.c_ulonglong),
        ("dport", ct.c_ulonglong),
        ("prot", ct.c_char * 32)
    ]


class Data_ipv6(ct.Structure):
    _fields_ = [
        ("cpu", ct.c_int),
        ("qu_idx", ct.c_ushort),
        ("data_len", ct.c_uint),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("lport", ct.c_ulonglong),
        ("dport", ct.c_ulonglong),
        ("prot", ct.c_char * 32)
    ]


def prep_idx(f_event, s_addr, d_addr):
    proto = f_event.prot.lower().replace("v6", "")
    s_tuple = "%s%s" % (s_addr, f_event.lport)
    d_tuple = "%s%s" % (d_addr, f_event.dport)
    flow_str = "%s%s%s" % (proto, s_tuple, d_tuple)
    return flow_str


def set_item(flows_hive, idx, f_event, s_addr, dst_addr):
    try:
        flows_hive[idx]['bytes'] = flows_hive[idx]['bytes'] + f_event.data_len
    except KeyError:
        # ugly k repetion
        item = {"cpu": f_event.cpu,
                "qu_idx": f_event.qu_idx,
                "bytes": f_event.data_len,
                "src_addr": s_addr,
                "src_p": f_event.lport,
                "dst_addr": dst_addr,
                "dst_p": f_event.dport,
                "type" : str(f_event.prot)}
        flows_hive[idx] = item


def gather_ipv4_flow(flows_hive, cpu, data, size):
    f_event = ct.cast(data, ct.POINTER(Data_ipv4)).contents

    s_addr = inet_ntop(AF_INET, pack('I', f_event.saddr))
    d_addr = inet_ntop(AF_INET, pack('I', f_event.daddr))

    idx = prep_idx(f_event, s_addr, d_addr)
    set_item(flows_hive, idx, f_event, s_addr, d_addr)


def gather_ipv6_flow(flows_hive, cpu, data, size):
    f_event = ct.cast(data, ct.POINTER(Data_ipv6)).contents

    s_addr = inet_ntop(AF_INET6, f_event.saddr)
    d_addr = inet_ntop(AF_INET6, f_event.daddr)

    idx = prep_idx(f_event, s_addr, d_addr)
    set_item(flows_hive, idx, f_event, s_addr, d_addr)

flows_hive_rx = {}
flows_hive_tx = {}

b = BPF(text=bpf_text)
b.attach_kprobe(event="dev_hard_start_xmit", fn_name="trace_tx_skb")
for _event in ["sctp_rcv", "dccp_v4_rcv", "dccp_v6_rcv",
               "udpv6_rcv", "udp_rcv", "tcp_v4_rcv", "tcp_v6_rcv"]:
    # some mods not default loaded/builtin
    try:
        b.attach_kprobe(event=_event, fn_name="trace_rx_skb")
    except Exception:
        # todo: intro dbg
        pass

b['ipv4_flows_rx'].open_perf_buffer(ft.partial(gather_ipv4_flow, flows_hive_rx))
b['ipv4_flows_tx'].open_perf_buffer(ft.partial(gather_ipv4_flow, flows_hive_tx))
b['ipv6_flows_rx'].open_perf_buffer(ft.partial(gather_ipv6_flow, flows_hive_rx))
b['ipv6_flows_tx'].open_perf_buffer(ft.partial(gather_ipv6_flow, flows_hive_tx))

# consider class
def run(interval):
    t_end = time.time() + interval
    while time.time() < t_end:
        b.kprobe_poll()

    return {'RX': flows_hive_rx, 'TX': flows_hive_tx}
