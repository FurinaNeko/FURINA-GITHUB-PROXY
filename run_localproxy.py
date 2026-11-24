"""打包入口（PyInstaller 用）。源码运行时等价于 python -m localproxy。"""

from __future__ import annotations

import sys

from localproxy.cli import main

if __name__ == "__main__":
    sys.exit(main())
