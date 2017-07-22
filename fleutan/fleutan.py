
# fleutan
#Copyright (C) 2017  Matthias Tafelmeier

#fleutan is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#fleutan is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program. If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import argparse
from concurrent import futures
from itertools import product
from tabulate import tabulate
from utils.util import flow_idx, _flows_e_exch, chunk_l
from ascii_graph.colors import *
import itertools
from interrogator import *
from depictor import *
import numpy as np
import collections


class Inciter:
    def __init__(self, focus, interrogator):
        self.focus = focus
        self.interrogator = interrogator
        self.core = getattr(self, self.focus, "unknown")

        if self.core == "unknown":
            raise RuntimeError("unknown focus")

    def __call__(self, args):
        self.core(args)

    # TODO relocate properly
    def _gather_flow_paths(self, filt_dsts):
        sys_interog = self.interrogator
        fut_to_f_dst_map = {}
        flow_paths = {}
        flows = sys_interog.gather_flows(with_if=False)
        if filt_dsts:
            # todo resolve dsts
            print filt_dsts
            flows = filter(lambda f: f['dst_addr'] in filt_dsts, flows)
            print flows
        # might setabl. workers num?
        with futures.ThreadPoolExecutor(max_workers=100) as executor:
            future = None
            for f in flows:
                # might hash f in fut?
                if f['dst_addr'] not in flow_paths.keys():
                    flow_paths[f['dst_addr']] = {'path': None, 'flows': [f]}
                    future = executor.submit(sys_interog.determine_path,
                                             f['dst_addr'])
                    fut_to_f_dst_map[future] = f['dst_addr']
                else:
                    flow_paths[f['dst_addr']]['flows'].append(f)

            done_iter = futures.as_completed(fut_to_f_dst_map)
            for future in done_iter:
                dst_addr_k = fut_to_f_dst_map[future]
                flow_paths[dst_addr_k]['path'] = future.result()

        return flow_paths

    def paths_load(self, args):
        flow_paths = self._gather_flow_paths()

        for f_p_k, f_p_v in flow_paths.items():
            sep_str = "-------"
            print("%s" % plot_path(f_p_v['path']))
            print(sep_str)
            for f in f_p_v['flows']:
                depict_flow(f, [])
            print(sep_str)

    def paths_delta_calc(self, hop):
        h_0 = hop[0]
        if isinstance(h_0, list):
            h_0 = h_0[0]

        for h in hop[1:]:
            if isinstance(h, list):
                if h_0 in h:
                    return False
            else:
                if h_0 == h:
                    return False
        return True

    def paths_delta(self, args):
        path_tables = []
        flow_paths = self._gather_flow_paths(args.dsts)
        raw_hops = [i_p['path']['hops'] for i_p in flow_paths.values()
                    if len(i_p['path']['hops']) > 0]
        legend = ['\n..>paths\n']
        header = ["(p%s)" % x for x in range(0, len(raw_hops))]

        print "**>Flows"
        for f_p_v, p_str in zip(flow_paths.values(), header):
            for f in f_p_v['flows']:
                depict_flow(f, [p_str])

        cols = 3
        for hop in itertools.izip_longest(*raw_hops):
            # todo refurb hop
            _hop = list(hop)
            if args.dsts and self.paths_delta_calc(_hop):
                _hop = color_hop_delta(_hop)

            if not path_tables:
                path_tables = [[list(r)] for r in chunk_l(_hop, cols)]
            else:
                idx = 0
                for pt_row in chunk_l(_hop, cols):
                    if pt_row:
                        path_tables[idx].append(list(pt_row))
                        idx = idx + 1

        print legend[0]
        for pt, _headers in itertools.izip_longest(path_tables, [list(x) for x in chunk_l(header, cols)]):
            print tabulate(pt, headers=_headers)

    def paths(self, args):
        # todo sophisticate indirector | depict
        if args.load:
            self.paths_load(args)
            return

        if args.delta:
            self.paths_delta(args)
            return

        raise RuntimeError("unknown paths interaction")

    def _flows_data_form(self, flows, func):
        idx_fmt = "%20s#%-6s%20s#%-6s"
        return [(idx_fmt % (f['src_addr'], f['src_p'], f['dst_addr'], f['dst_p']),
                             func(f)) for f in flows]

    def _flows_group(self, flow_groups):
            flow_groups = []
            k_func = None
            if args.group == 'peer':
                k_func = lambda f: f['dst_addr']
                label_pre = 'dst'
            elif args.group == 'proc':
                k_func = lambda f: f['pid']
                label_pre = 'proc'
            else:
                raise RuntimeError('Unexpected aspect %s' % args.group)

            flows = sorted(flows, key=k_func)
            for k, g in itertools.groupby(flows, k_func):
                flow_groups.append(list(g))
                if args.group == 'proc':
                    k = "%s (%s)" % (self.interrogator.resolve_pid(int(k)), k)
                flow_group_k.append(k)

            return flow_group_k, flow_groups

    def flows_vol(self, args):
        flows = filter(lambda x: x['type'] == 'tcp' and 'tcp_rtt' in x.keys(), self.interrogator.gather_flows(with_if=False))
        flow_groups = [flows]
        flow_group_k = []
        label_pre = ""

        if args.group:
            flow_group_k, flow_groups = self._flows_group(flows)


        print("**TCP FLOWS:ebdp (estimated bandwidth-delay-product)")
        for f_group, k in itertools.izip_longest(flow_groups, flow_group_k):
            label = ""
            if k:
                label = "%s>>%s" % (label_pre, k)
            func = lambda f: f['tcp_cwnd'] * f['tcp_rtt']
            ebwp_data = self._flows_data_form(f_group, func)

            plot_bars(label, sorted(ebwp_data, key=lambda v: v[1]), "-")
            print "\n---"

        print("**TCP FLOWS: transceive stats")
        for k, intercept_flows in self.interrogator.survey_flows(args.interval).items():
            post_f = 'in'
            g_sym = '|'
            if k == 'TX':
                post_f = 'out'
                g_sym = '*'
            _flows_e_exch(flows, intercept_flows, ['tcp_segs_%s' % post_f], ['tcp_segs_%s' % post_f])
            _intercept_flows = filter(lambda x: x['type'].startswith('TCP'), intercept_flows.values())

            print(">>%s" % (k))
            for data_idx, _flows in {'tcp_segs_%s' % post_f: flows, 'bytes': _intercept_flows}.items():
                label = "##%s" % (data_idx)
                func = lambda f: f[data_idx]
                b_vol_data = self._flows_data_form(_flows, func)
                plot_bars(label, sorted(b_vol_data, key=lambda v: v[1]), g_sym)
            print "\n---"


    def flows_cpu(self, args):
        flows = self.interrogator.gather_flows()
        cpu_asoc = self.interrogator.scout_p_cpus([f['pid'] for f in flows], interval=args.interval)
        cpus_num = self.interrogator.determine_cpu_num()

        if args.cpu == 'gen':
            label = "flow processing load distribution:"
            # ugly repetition
            _flows = filter(lambda x: x['type'] == 'tcp' and 'tcp_segs_out' in x.keys(), flows)
            print _flows
            loads = {}
            for k, func in {
                    "segs_in":  lambda f: f['tcp_segs_in'],
                    "segs_out": lambda f: f['tcp_segs_out'],
                    "ebwp":  lambda f: f['tcp_cwnd'] * f['tcp_rtt']
                    }.items():
                loads[k] = {f['pid']: func(f) for f in _flows}

            e_k = 'bytes'
            for k, intercept_flows in self.interrogator.survey_flows(args.interval).items():
                _flows_e_exch(flows, intercept_flows, ['pid'], ['pid'])
                _intercept_flows = filter(lambda x: 'pid' in x.keys(), intercept_flows.values())
                loads['%s_%s' % (k, e_k)] = {f['pid']: f[e_k] for f in _intercept_flows}

            for k, _load in loads.items():
                l_out_data = [[cpu, 0] for cpu in range(0, cpus_num)]
                for pid, hist in cpu_asoc.items():
                    if pid in _load.keys():
                        c = collections.Counter(hist)
                        for tup in l_out_data:
                            prop = c[tup[0]]/float((len(hist)))
                            tup[1] = tup[1] + prop * _load[pid]

                # since tuples immutable
                l_out_data = [ tuple(l) for l in l_out_data ]
                label = "#>%s" % (k)
                plot_bars(label, l_out_data)


        if args.cpu == 'fl_asoc':
            for pid, hist in cpu_asoc.items():
                cur_flows = filter(lambda f: f['pid'] == pid, flows)
                print("~>%s(%s)" % (self.interrogator.resolve_pid(pid), pid))
                for f in sorted(cur_flows, key=lambda f: f['type']):
                    print("%-10s%20s#%-20s%20s#%s" %
                          (f['type'], f['src_addr'], f['src_p'], f['dst_addr'], f['dst_p']))

                print("___")
                c = collections.Counter(hist)
                out_data = [(cpu, c[cpu]) for cpu in range(0, cpus_num)]
                plot_bars("", out_data)
                #plot
                print("...")

    def flows_lat(self, args):
        flows = filter(lambda x: x['type'] == 'tcp' and 'tcp_rtt' in x.keys(), self.interrogator.gather_flows(with_if=False))
        # depupl from vol!
        flow_groups = [flows]
        flow_group_k = []
        label_pre = ""

        if args.group:
            flow_group_k, flow_groups = self._flows_group(flows)

        print("**TCP FLOWS: (NUM %s)" % len(flows))
        print("*latency distribution [rtt-range]")
        rtt_a = [f['tcp_rtt'] for f in flows]
        hist, bins = np.histogram(rtt_a)
        label = ""
        keys = ["[%s-%s]" % (x, y) for x, y in zip(bins[:-1], bins[1:])]
        lat_data = [(x, y) for x, y in zip(keys, hist)]

        plot_bars(label, lat_data)
        print "\n---"

        thresholds = {}
        for t, col in zip(args.thresh.split(','), [Gre, Yel, Red]):
            thresholds[int(t)] = col

        print("*latency per flow in rtt(ms)")
        for f_group, k in itertools.izip_longest(flow_groups, flow_group_k):
            label = ""
            if k:
                label = "%s>>%s" % (label_pre, k)
            func = lambda f: f['tcp_rtt']
            lat_data = self._flows_data_form(f_group, func)

            plot_bars(label, sorted(lat_data, key=lambda v: v[1]), threshs=thresholds)
            print "\n---"


    def flows(self, args):
        if args.lat:
            self.flows_lat(args)
            return

        if args.vol:
            self.flows_vol(args)
            return

        if args.cpu:
            self.flows_cpu(args)
            return

        raise RuntimeError("unknown flows interaction")


def init_args():
    # todo systematic descr/CLI doc
    parser = argparse.ArgumentParser(description="Fleutan - a scalable flowing and pathing wielding lever")

    subparsers = parser.add_subparsers(description="Focus selectable via sub modules hierarchy.", dest="focus")

    paths_parser = subparsers.add_parser('paths')
    paths_parser.add_argument('-l', '--load', help='centre on of flows traversed net paths', action='store_true')
    paths_parser.add_argument('-d', '--delta', help='show deltas of paths of existing flows', action='store_true')
    paths_parser.add_argument('--dsts', help='peer destinations to focus on', nargs='*', metavar=('dst1 dst2', ''))

    flows_parser = subparsers.add_parser('flows')
    flows_parser.add_argument('-l', '--lat', help='show latency(rtt) outline of flows (TCP only)', action='store_true')
    flows_parser.add_argument('-t', '--thresh', help='specify thresholds for categorizations', default="10,20,100", metavar='t1,t2,t3')
    flows_parser.add_argument('-v', '--vol', help='show volume outline of flows (TCP only)', action='store_true')
    flows_parser.add_argument('-c', '--cpu', help='show cpu related stats', choices=['gen', 'fl_asoc'])
    flows_parser.add_argument('-g', '--group', help='group treat flows as of specified indepentend aspect',
                              choices=['peer', 'proc'])
    # too groase
    flows_parser.add_argument('-i', '--interval', help='interval in secs for sampling based functionalities',
                              type=int, default=2)

    args = parser.parse_args()

    return args


def run():
    args = init_args()
    sys_interog = Interrogator()

    Inciter(args.focus, sys_interog)(args)
