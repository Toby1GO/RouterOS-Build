"""Small desktop frontend for the existing x86 and experimental CHR signers."""
import ctypes
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from license import generate, hex_key, normalize_id, public_from_private, read_keys, verify
from chr_license import decode_system_id, generate_chr, verify_chr

X86 = 'x86 / RouterOS 7 · L6'
CHR = 'CHR · System ID（实验）'
CHR_LEVELS = {'p1': 1, 'p10': 2, 'p-unlimited': 3}


def app_dir():
    return Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent


def default_key_file():
    for path in (app_dir() / 'signing.env', app_dir() / '.private' / 'signing.env',
                 Path(__file__).resolve().parent / 'resources' / 'signing.env'):
        if path.is_file():
            return path
    return app_dir() / '.private' / 'signing.env'


def make_license(mode, identity, path, level=3):
    """Shared worker entry point. Never return or display private key values."""
    if mode == X86:
        identity = normalize_id(identity)
    elif mode == CHR:
        identity = identity.strip()
        decode_system_id(identity)
    else:
        raise ValueError('未知授权类型')
    keys = read_keys(path)
    private = hex_key(keys['CUSTOM_LICENSE_PRIVATE_KEY'])
    public = hex_key(keys['CUSTOM_LICENSE_PUBLIC_KEY'])
    if public_from_private(private) != public:
        raise ValueError('密钥文件中的许可证公钥与私钥不匹配')
    if mode == X86:
        text = generate(identity, private)
        result = verify(text, public)
        if result['software_id'] != identity:
            raise ValueError('生成结果的 Software ID 不匹配')
    else:
        text = generate_chr(identity, private, 0xf4865700, level)
        result = verify_chr(text, public)
        if result['system_id'] != identity or result['level'] != level:
            raise ValueError('生成结果的 System ID 或等级不匹配')
    return identity, text


class LicenseWindow:
    def __init__(self, root):
        self.root = root
        root.title('RouterOS 授权生成器')
        root.geometry('780x650')
        root.minsize(700, 610)
        root.configure(bg='#f4f6f9')
        style = ttk.Style(root)
        if 'vista' in style.theme_names():
            style.theme_use('vista')
        style.configure('TFrame', background='#f4f6f9')
        style.configure('TLabel', background='#f4f6f9', font=('Microsoft YaHei UI', 10))
        style.configure('Title.TLabel', font=('Microsoft YaHei UI', 19, 'bold'))
        style.configure('TButton', font=('Microsoft YaHei UI', 10), padding=(12, 7))
        self.mode = tk.StringVar(value=X86)
        self.identity = tk.StringVar()
        self.key_file = tk.StringVar(value=str(default_key_file()))
        self.level = tk.StringVar(value='p-unlimited')
        self.status = tk.StringVar(value='粘贴设备 ID，然后点击 Generate。')
        self.result = ''
        self.result_id = ''
        self.busy = False
        self.jobs = queue.Queue()
        frame = ttk.Frame(root, padding=24)
        frame.pack(fill='both', expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(8, weight=1)
        ttk.Label(frame, text='RouterOS 授权生成器', style='Title.TLabel').grid(row=0, column=0, sticky='w')
        ttk.Label(frame, text='使用现有自有密钥 · 本地生成 · 无需命令行').grid(row=1, column=0, sticky='w', pady=(4, 18))
        top = ttk.Frame(frame)
        top.grid(row=2, column=0, sticky='ew')
        top.columnconfigure(0, weight=1)
        self.mode_box = ttk.Combobox(top, textvariable=self.mode, values=[X86, CHR], state='readonly', width=33)
        self.mode_box.grid(row=0, column=0, sticky='w')
        self.level_label = ttk.Label(top, text='CHR 等级')
        self.level_label.grid(row=0, column=1, padx=(12, 6))
        self.level_box = ttk.Combobox(top, textvariable=self.level, values=list(CHR_LEVELS), state='disabled', width=14)
        self.level_box.grid(row=0, column=2)
        self.id_label = ttk.Label(frame, text='Software ID（例如 KUC1-6JNF）')
        self.id_label.grid(row=3, column=0, sticky='w', pady=(14, 5))
        id_row = ttk.Frame(frame)
        id_row.grid(row=4, column=0, sticky='ew')
        id_row.columnconfigure(0, weight=1)
        self.id_entry = ttk.Entry(id_row, textvariable=self.identity, font=('Consolas', 15))
        self.id_entry.grid(row=0, column=0, sticky='ew', ipady=5)
        self.paste_button = ttk.Button(id_row, text='粘贴 ID', command=self.paste)
        self.paste_button.grid(row=0, column=1, padx=(10, 0))
        self.generate_button = ttk.Button(id_row, text='Generate', command=self.generate)
        self.generate_button.grid(row=0, column=2, padx=(10, 0))
        self.note = ttk.Label(frame, text='', wraplength=710)
        self.note.grid(row=5, column=0, sticky='ew', pady=(9, 12))
        key_row = ttk.Frame(frame)
        key_row.grid(row=6, column=0, sticky='ew', pady=(0, 14))
        key_row.columnconfigure(0, weight=1)
        ttk.Label(key_row, text='密钥文件（signing.env）').grid(row=0, column=0, sticky='w')
        self.key_entry = ttk.Entry(key_row, textvariable=self.key_file)
        self.key_entry.grid(row=1, column=0, sticky='ew', pady=(4, 0))
        self.browse_button = ttk.Button(key_row, text='选择文件…', command=self.browse)
        self.browse_button.grid(row=1, column=1, padx=(10, 0))
        ttk.Label(frame, text='授权文本').grid(row=7, column=0, sticky='w', pady=(0, 5))
        self.output = tk.Text(frame, height=7, wrap='none', font=('Consolas', 10), bg='white',
                              relief='solid', borderwidth=1, padx=12, pady=12, state='disabled')
        self.output.grid(row=8, column=0, sticky='nsew')
        actions = ttk.Frame(frame)
        actions.grid(row=9, column=0, sticky='ew', pady=(10, 8))
        self.copy_button = ttk.Button(actions, text='复制完整 Key', command=self.copy, state='disabled')
        self.copy_button.pack(side='left')
        ttk.Label(frame, textvariable=self.status, wraplength=710).grid(row=10, column=0, sticky='ew')
        self.mode.trace_add('write', self.mode_changed)
        for value in (self.identity, self.key_file, self.level):
            value.trace_add('write', self.invalidate)
        root.bind('<Return>', lambda event: self.generate())
        root.after(80, self.poll)
        self.mode_changed()
        self.id_entry.focus_set()

    def invalidate(self, *_):
        self.result = ''
        self.result_id = ''
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.configure(state='disabled')
        self.copy_button.configure(state='disabled')
        if not self.busy:
            self.status.set('粘贴设备 ID，然后点击 Generate。')

    def mode_changed(self, *_):
        self.identity.set('')
        chr_mode = self.mode.get() == CHR
        self.level_box.configure(state='readonly' if chr_mode else 'disabled')
        self.id_label.configure(text='System ID（11 位，区分大小写）' if chr_mode else 'Software ID（例如 KUC1-6JNF）')
        self.note.configure(text=('CHR 实验模式：设备激活、等级和有效期仍需验证；当前沿用测试有效期字段。'
                                  if chr_mode else '适用于使用你公钥的 RouterOS 7 镜像；安装后读取实际 Software ID。'))
        self.invalidate()

    def paste(self):
        try:
            value = self.root.clipboard_get()
            self.identity.set(value.strip())
        except tk.TclError:
            self.status.set('剪贴板中没有可粘贴的文本。')

    def browse(self):
        name = filedialog.askopenfilename(parent=self.root, title='选择现有 signing.env',
                                          filetypes=[('密钥文件', '*.env'), ('所有文件', '*.*')])
        if name:
            self.key_file.set(name)

    def set_busy(self, busy):
        self.busy = busy
        for widget in (self.id_entry, self.key_entry, self.paste_button, self.browse_button, self.generate_button):
            widget.configure(state='disabled' if busy else 'normal')
        self.mode_box.configure(state='disabled' if busy else 'readonly')
        self.level_box.configure(state='readonly' if not busy and self.mode.get() == CHR else 'disabled')

    def generate(self):
        if self.busy:
            return
        self.invalidate()
        mode, identity, path, level = self.mode.get(), self.identity.get(), self.key_file.get(), CHR_LEVELS[self.level.get()]
        self.set_busy(True)
        self.status.set('正在生成并校验签名…')
        def worker():
            try:
                result = make_license(mode, identity, Path(path), level)
                self.jobs.put(('ok', result))
            except FileNotFoundError:
                self.jobs.put(('error', '未找到密钥文件，请选择你现有的 signing.env。'))
            except PermissionError:
                self.jobs.put(('error', '无法读取密钥文件，请检查文件权限。'))
            except KeyError:
                self.jobs.put(('error', '密钥文件缺少许可证公钥或私钥字段。'))
            except ValueError:
                self.jobs.put(('error', '请检查 ID 格式及密钥文件：x86 为 XXXX-XXXX；CHR 为 11 位且区分大小写，密钥必须配对。'))
            except Exception:
                self.jobs.put(('error', '生成失败。请检查密钥文件格式及程序文件是否完整。'))
        threading.Thread(target=worker, daemon=True).start()

    def poll(self):
        try:
            kind, value = self.jobs.get_nowait()
        except queue.Empty:
            pass
        else:
            self.set_busy(False)
            if kind == 'error':
                self.status.set(value)
            else:
                self.result_id, self.result = value
                self.output.configure(state='normal')
                self.output.insert('1.0', self.result)
                self.output.configure(state='disabled')
                self.copy_button.configure(state='normal')
                suffix = 'CHR 实机激活仍待验证。' if self.mode.get() == CHR else '请复制完整文本到对应设备。'
                self.status.set(f'已生成：{self.result_id}，签名自检通过。{suffix}')
        self.root.after(80, self.poll)

    def copy(self):
        if self.result:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.result)
            self.status.set('完整 Key 已复制，可粘贴到对应设备。')

def self_test(report_path):
    """Exercise the frozen GUI and signing dependencies without exposing keys."""
    import json
    key_path = default_key_file()
    make_license(X86, 'KUC1-6JNF', key_path)
    make_license(CHR, 'AAAAAAAAAAA', key_path)
    root = tk.Tk()
    root.withdraw()
    try:
        LicenseWindow(root)
        root.update()
        report = {'ok': True, 'python': sys.version.split()[0],
                  'frozen': bool(getattr(sys, 'frozen', False)),
                  'key_source': 'embedded' if key_path.parent.name == 'resources' else 'external',
                  'checks': ['x86 sign/verify', 'CHR sign/verify', 'Tk window'],
                  'tcl': root.tk.call('info', 'patchlevel')}
    finally:
        root.destroy()
    Path(report_path).write_text(json.dumps(report, indent=2), encoding='utf-8')


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--self-test':
        self_test(sys.argv[2])
        return
    if sys.platform == 'win32':
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    LicenseWindow(root)
    root.mainloop()


if __name__ == '__main__':
    main()
