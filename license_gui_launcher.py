"""Keep startup diagnostics available even if importing the GUI fails."""
import ctypes
import os
import sys
import tempfile
import traceback
from pathlib import Path


def run():
    try:
        from license_gui import main
        main()
    except Exception:
        folder = Path(os.environ.get('LOCALAPPDATA', tempfile.gettempdir())) / 'RouterOSKeygen'
        try:
            folder.mkdir(parents=True, exist_ok=True)
            log = folder / 'startup-error.log'
            log.write_text(traceback.format_exc(), encoding='utf-8')
            message = f'程序启动失败，诊断日志已保存到：\n{log}'
        except OSError:
            message = '程序启动失败，且无法写入诊断日志。请检查用户目录权限。'
        if '--self-test' not in sys.argv and sys.platform == 'win32':
            ctypes.windll.user32.MessageBoxW(None, message, 'RouterOS 授权生成器', 0x10)
        raise SystemExit(1)


if __name__ == '__main__':
    run()
