
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

from utils.util import which
import re
import subprocess
import psutil
import collections
import time
import multiprocessing
try:
    from functools import lru_cache
except ImportError:
    from backports.functools_lru_cache import lru_cache


class ParseException(Exception):
    pass


class Interrogator:

    path_hop_re = re.compile(r"\w\s+?([\w\d\.\:]+?)\s\((.+)")

    # flows patterns
    flow_types = ['tcp', 'raw', 'udp', 'dccp']
    flow_decolate_re = re.compile(r"(%s)" % ("|".join(flow_types)))

    ip_r_dev_re = re.compile("dev\s+?(?P<dev>\w+)\\b")

    ip_v4_addr_sub_re = "([0-9]{1,3}\.){3}[0-9]{1,3}(:\d+)"
    # ref.: to commented, untinkered version: ISBN 978-0-596-52068-7
    ip_v6_addr_sub_re = "(?:(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|"\
                        "(?=(?:[A-F0-9]{0,4}:){0,7}[A-F0-9]{0,4})"\
                        "(([0-9A-F]{1,4}:){1,7}|:)((:[0-9A-F]{1,4})"\
                        "{1,7}|:))(:\d+)"

    pid_re = re.compile(r"pid=(?P<pid>\d+)", re.MULTILINE)
    ip_v4_endp_re = re.compile(r"" + "(?P<src_ep>" + ip_v4_addr_sub_re + ")" +
                               "\s+" + "(?P<dst_ep>" + ip_v4_addr_sub_re + ")")
    ip_v6_endp_re = re.compile(r"" + "(?P<src_ep>" + ip_v6_addr_sub_re + ")" +
                               "\s+" + "(?P<dst_ep>" + ip_v6_addr_sub_re + ")",
                               re.IGNORECASE)

    data_res = [re.compile(r"cwnd:(?P<cwnd>\d+)", re.MULTILINE),
                re.compile(r"rtt:(?P<rtt>\d+\.\d+)/(?P<rtt_var>\d+\.\d+)",
                           re.MULTILINE),
                re.compile(r"segs_out:(?P<segs_out>\d+)\s+segs_in:(?P<segs_in>\d+)",
                           re.MULTILINE)]

    def __init__(self):
        pass

    def scout_p_cpus(self, pids, interval=2, delta=0.1):
        res = dict.fromkeys(pids)
        for p in pids:
            res[p] = {'p': psutil.Process(int(p)), 'cpu_stat': []}

        #todo sophisticate/tune this
        t_end = time.time() + interval
        while time.time() < t_end:
            for p in pids:
                res[p]['cpu_stat'].append(res[p]['p'].cpu_num())

            time.sleep(delta)

        for k, v in res.items():
            del v['p']
            res[k] = v['cpu_stat']

        return res

    def determine_cpu_num(self):
        return multiprocessing.cpu_count()

    def determine_path(self, peer):
        res = {'hops': []}
        cmd = which('traceroute')
        if cmd:
            p_exec = subprocess.Popen("%s %s" % (cmd, peer),
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      shell=True)
            out, err = p_exec.communicate()

            if p_exec.returncode != 0:
                raise RuntimeError("path not determineable for %s: %s" % (peer, err))

            for line in out.splitlines():
                hop_agglom = []
                for sub_line in line.split(')'):
                    _hop_match = self.path_hop_re.search(sub_line)
                    if _hop_match:
                        try:
                            res_attempt_hop = _hop_match.group(1)
                            # not relevant atm
                            # canonic_hop = _hop_match.group(1)
                            if res_attempt_hop:
                                hop_agglom.append(res_attempt_hop)
                        except:
                            raise RuntimeError("Unexpected hop outline")
                if len(hop_agglom) == 1:
                    res['hops'].append(hop_agglom[0])
                elif len(hop_agglom) > 1:
                    res['hops'].append(hop_agglom)
        else:
            raise RuntimeError("cannot find path determination tool")

        # droping peer tgt
        res['hops'] = res['hops'][1:]
        return res

    def _parse_val(self, val):
        if val.endswith("Mbps"):
            return float(val[:-4])
        if val.endswith("Kbps"):
            return float(val[:-4])*1000
        if val.endswith("bps"):
            return float(val[:-3])*10**6
        return float(val)

    def _dissect_ep(self, whole):
        shards = whole.split(":")
        addr = None
        # cure by checking ip_version
        if len(shards) > 2:
            addr = ":".join(shards[:-1])
        else:
            addr = ".".join(shards[:-1])

        port = shards[-1]

        return addr, port

    @lru_cache(maxsize=1024, typed=False)
    def determine_fl_dev(self, dst):
        cmd = which('ip')
        args = 'r get %s' % dst
        if cmd:
            p_exec = subprocess.Popen("%s %s" % (cmd, args),
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      shell=True)
            out, err = p_exec.communicate()

            if p_exec.returncode != 0:
                raise RuntimeError("dev not gatherable for: %s\n%s" % (dst, err))

            dev_match =  self.ip_r_dev_re.search(out)

            return dev_match.group('dev')
        else:
            raise RuntimeError("cannot find flow dev determination tool")

    def _parse_flow(self, matter):
        # matter = matter.strip()
        fl_end_p = self.ip_v4_endp_re.search(matter)
        if None is fl_end_p:
            fl_end_p = self.ip_v6_endp_re.search(matter)

        if None is fl_end_p:
            raise ParseException("Unexpected flows outline")

        src_addr, src_p = self._dissect_ep(fl_end_p.group('src_ep'))
        dst_addr, dst_p = self._dissect_ep(fl_end_p.group('dst_ep'))
        pid = self.pid_re.search(matter).group('pid')

        res = {"src_addr": src_addr,
               "src_p": src_p,
               "dst_addr": dst_addr,
               "dst_p": dst_p,
               "pid": pid}

        for r in self.data_res:
            m = r.search(matter)
            if m is not None:
                d = m.groupdict()
                for k, v in d.items():
                    try:
                        res['tcp_%s' % k] = self._parse_val(v)
                    except ValueError:
                        pass

        return res

    # todo - selectiveness for efficiency
    def gather_flows(self, with_if=True):
        # TODO shift to more efficient ways (e.g. sk dumping)
        flows = []
        cmd = which('ss')
        # only ones with remote peering potential
        opts = '-tudwp -n -i'
        if cmd:
            p_exec = subprocess.Popen("%s %s" % (cmd, opts),
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      shell=True)
            out, err = p_exec.communicate()

            if p_exec.returncode != 0:
                raise RuntimeError("flows not gatherable for: %s" % (err))

            flows_raw = self.flow_decolate_re.split(out)
            # skip head
            flows_raw = flows_raw[1:]
            for flow_type, flow in zip(flows_raw[0::2], flows_raw[1::2]):
                refined_flow = self._parse_flow(flow)
                refined_flow['type'] = flow_type
                if with_if:
                    refined_flow['dev'] = self.determine_fl_dev(refined_flow['dst_addr'])
                flows.append(refined_flow)

        else:
            raise RuntimeError("cannot find flows determination tool")

        return flows

    def resolve_pid(self, pid):
        p = psutil.Process(int(pid))
        return " ".join(p.cmdline())

    def survey_flows(self, interval):
        import flow_interceptor
        return flow_interceptor.run(interval)
