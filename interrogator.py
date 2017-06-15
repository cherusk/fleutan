
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

from utils import utils
import re

class interrogator:

    path_hop_re = re.compile("\b(.+?)\b \((.+)")

    def __init__(self):
        pass

    def determine_path(peer):
        cmd = utils.which('traceroute')

        if cmd:
            p_exec = subprocess.Popen([cmd, peer],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        shell=True)
            out, err = proc.communicate()

            if p_exec.returncode != 0:
                raise RuntimeError("path not determineable for %s: %s" % (peer, err)) 

            for line in out:
                #todo regex action
                print line
        else:
            raise RuntimeError("cannot find path determination tool") 

