
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
import itertools
from interrogator import *
from depictor import *


sys.path.insert(1, os.path.dirname(__file__))


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
    def _gather_flow_paths(self):
        sys_interog = self.interrogator
        fut_to_f_dst_map = {}
        flow_paths = {}
        flows = sys_interog.gather_flows()
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
                print("%-10s%20s#%-20s%20s#%s" %
                      (f['type'], f['src_addr'], f['src_p'], f['dst_addr'], f['dst_p']))
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
        path_table = []
        flow_paths = self._gather_flow_paths()
        raw_hops = [i_p['path']['hops'] for i_p in flow_paths.values()
                    if len(i_p['path']['hops']) > 0]
        legend = ['\n..>paths\n']
        header = ["p%s" % x for x in range(0, len(raw_hops))]

        # depulicate!
        print "**>Flows"
        for f_p_v,p_str in zip(flow_paths.values(), header):
            for f in f_p_v['flows']:
                print("%-10s%20s#%-20s%20s#%s%10s" %
                      (f['type'], f['src_addr'], f['src_p'], f['dst_addr'], f['dst_p'], p_str))


        for hop in itertools.izip_longest(*raw_hops):
            # todo refurb hop
            _hop = list(hop)
            #if self.paths_delta_calc(_hop):
                #_hop = color_hop_delta(_hop)
            path_table.append(_hop)

        print legend[0]
        print tabulate(path_table, headers=header)

    def paths(self, args):
        # todo sophisticate indirector | depict
        if args.load:
            self.paths_load(args)
            return

        if args.delta:
            self.paths_delta(args)
            return

        raise RuntimeError("unknown paths interaction")

    def flows_vol_data_form(self, flows, func):
        idx_fmt = "%20s#%-6s%20s#%-6s"
        return [(idx_fmt % (f['src_addr'], f['src_p'], f['dst_addr'], f['dst_p']),
                             func(f)) for f in flows]

    def flows_vol(self, args):
        flows = filter(lambda x: x['type'] == 'tcp', self.interrogator.gather_flows())
        flow_groups = [flows]
        flow_group_k = []
        label_pre = ""

        if args.group:
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

        print("**TCP FLOWS:ebdp (estimated bandwidth-delay-product)")
        for f_group, k in itertools.izip_longest(flow_groups, flow_group_k):
            label = "%s>>%s" % (label_pre, k)
            func = lambda f: f['tcp_cwnd'] * f['tcp_rtt']
            ebwp_data = self.flows_vol_data_form(f_group, func)

            plot_bars(label, sorted(ebwp_data, key=lambda v: v[1]))
            print "\n---"

    def flows(self, args):
        if args.vol:
            self.flows_vol(args)
            return

        raise RuntimeError("unknown flows interaction")


def init_args():
    # todo systematic descr/CLI doc
    parser = argparse.ArgumentParser(description="Fleutan - a scalable flow and path wielding lever")

    subparsers = parser.add_subparsers(description="focus moduls", dest="focus")

    paths_parser = subparsers.add_parser('paths')
    paths_parser.add_argument('-l', '--load', help='centre flows traversed net paths', action='store_true')
    paths_parser.add_argument('-d', '--delta', help='show deltas of paths', action='store_true')

    flows_parser = subparsers.add_parser('flows')
    flows_parser.add_argument('-v', '--vol', help='show volume outline of flows (TCP only)', action='store_true')
    flows_parser.add_argument('-g', '--group', help='group treat flows as of specified indepentend aspect',
                              choices=['peer', 'proc'])

    args = parser.parse_args()

    return args


def run():
    args = init_args()
    sys_interog = Interrogator()

    Inciter(args.focus, sys_interog)(args)


if __name__ == "__main__":
    run()
