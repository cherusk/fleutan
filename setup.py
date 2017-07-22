from distutils.core import setup

setup(
  name='Fleutan',
  packages=['fleutan', 'fleutan.utils'],
  license="GPL-3.0",
  version='0.7',
  description="Fleutan - a scalable network flows and paths wielding lever",
  author='Matthias Tafelmeier',
  author_email='matthias.tafelmeier@gmx.net',
  scripts=['./fleutan/fleutan'],
  url='https://github.com/cherusk/fleutan',
  download_url='https://github.com/cherusk/fleutan/dist/0.7.tar.gz',
  install_requires=['tabulate', 'futures', 'ascii_graph', 'numpy', 'psutil', 'multiprocessing', 'backports.functools_lru_cache', 'termcolor' ],
  keywords=['linux', 'tool', 'transport', 'sockets', 'flow', 'stats', 'analytics'],
  classifiers=[],
)
