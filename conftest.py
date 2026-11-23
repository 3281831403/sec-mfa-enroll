"""让 unit 与 behaviour 两个测试目录都能导入仓库根下的 mfa 包。"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
