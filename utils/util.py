
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

def is_executable(filename):
    return os.path.isfile(filename) and os.access(filename, os.X_OK)


def which(executable, fail=False):
    pathname, filename = os.path.split(executable)
    if pathname:
        if is_executable(executable):
            return executable
    else:
        for path in [i.strip('""') for i in os.environ["PATH"].split(os.pathsep)]:
            filename = os.path.join(path, executable)
            if is_executable(filename):
                return filename

    if fail:
        raise RuntimeError("No %s binary found in PATH." % executable)
    return None
