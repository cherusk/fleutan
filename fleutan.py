
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
from interrogator import *
from depictor import *

sys.path.insert(1, os.path.dirname(__file__))


def init_args():
    # todo systematic descr/CLI doc
    parser = argparse.ArgumentParser(description="Fleutan - a scalable flow and path wielding lever")

    subparsers = parser.add_subparsers(description="focus moduls", dest="focus")

    paths_parser = subparsers.add_parser('paths')
    paths_parser.add_argument('-l', '--load', help='centre flows traversed net paths', action='store_true')

    args = parser.parse_args()

    return args


def run():

    args = init_args()
    sys_interog = Interrogator()

    # todo sophisticate indirector | depict
    if args.focus == "paths" and args.load:
        flow_paths = {}
        flows = sys_interog.gather_flows()
        for f in flows:
            # might hash f in fut?
            if f['dst_addr'] not in flow_paths.keys():
                f_path = sys_interog.determine_path(f['dst_addr'])
                flow_paths[f['dst_addr']] = {'path': f_path, 'flows': [f]}
            else:
                flow_paths[f['dst_addr']]['flows'].append(f)

        for f_p_k, f_p_v in flow_paths.items():
            sep_str = "-------"
            print("%s" % plot_path(f_p_v['path']))
            print(sep_str)
            for f in f_p_v['flows']:
                print("%-10s%20s#%-20s%20s#%s" % (f['type'], f['src_addr'], f['src_p'], f['dst_addr'], f['dst_p']))
            print(sep_str)

if __name__ == "__main__":
    run()
