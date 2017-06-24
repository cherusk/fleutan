
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


def plot_path(path):
    hops = path['hops']
    path_depict = ""
    connect_str = ""
    h_depict = "|%s|"
    h_fan_depict = "||%s||"
    for h in hops:
        curr_dep = ""
        if isinstance(h, list):
            for fan_h in h:
                if curr_dep:
                    curr_dep = "%s|%s" % (curr_dep, fan_h)
                else:
                    curr_dep = "%s" % (fan_h)

            curr_dep = h_fan_depict % (curr_dep)
        else:
            curr_dep = h_depict % h

        path_depict = "%s%s%s" % (path_depict, connect_str, curr_dep)
        connect_str = " <---> "

    return path_depict