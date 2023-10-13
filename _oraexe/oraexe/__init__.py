"""
PE文件解析文件
"""


def _get_name_iter(bt: bytes, foa: int):
    while True:
        if bt[foa] == 0:
            return
        yield bt[foa]
        foa += 1


def _get_name(bt: bytes, foa: int) -> str:
    return bytes(_get_name_iter(bt, foa)).decode("ascii")


class P1:
    """Exe解析类"""
    def __init__(self, bt: bytes):
        #基本信息
        self.cblp = int.from_bytes(bt[0x02:0x04], "little")
        self.cp = int.from_bytes(bt[0x04:0x06], "little")
        lfanew = int.from_bytes(bt[0x3c:0x40], "little")
        self.lfanew = lfanew
        self.checksum = bt[lfanew + 0x58:lfanew + 0x5c]
        self.magic = bt[lfanew + 0x18:lfanew + 0x1a]
        self.machine = bt[lfanew + 0x04:lfanew + 0x06]
        self.start = int.from_bytes(bt[lfanew + 0x28:lfanew + 0x2c], "little")
        self.imbase = int.from_bytes(bt[lfanew + (0x34 if self.magic == b"\x0b\x01" else 0x30)
                                        :lfanew + 0x38], "little")
        self.csum = bt[0x12:0x14]
        #节表
        self.secs = [
            {
                "virsual_addr": int.from_bytes(bt[addr + (0x0c if self.magic == b"\x0b\x01" else 0x10):
                                                  addr + (0x10 if self.magic == b"\x0b\x01" else 0x14)], "little"), 
                "file_addr": int.from_bytes(bt[addr + (0x14 if self.magic == b"\x0b\x01" else 0x18):
                                               addr + (0x18 if self.magic == b"\x0b\x01" else 0x1c)], "little"), 
                "virsual_size": int.from_bytes(bt[addr + (0x10 if self.magic == b"\x0b\x01" else 0x14):
                                                  addr + (0x14 if self.magic == b"\x0b\x01" else 0x18)], "little"), 
                "name": bt[addr:addr + 0x08].decode("ascii")}
            for addr in range(lfanew + (0xf8 if self.magic == b"\x0b\x01" else 0x108), lfanew
                               + (0xf8 if self.magic == b"\x0b\x01" else 0x108) + (0x28 if self.magic == b"\x0b\x01" else 0x50)
                                 * int.from_bytes(bt[lfanew + 0x06:lfanew + 0x08], "little"), 
                                 (0x28 if self.magic == b"\x0b\x01" else 0x50))
        ]
        #导入表
        self.import_tb_addr = self.foa(int.from_bytes(bt[lfanew + (0x80 if self.magic == b"\x0b\x01" else 0xa0):
                                                    lfanew + (0x84 if self.magic == b"\x0b\x01" else 0xa4)], "little"))
        self.import_tb = []
        for import_seg_addr in range(self.import_tb_addr, self.import_tb_addr + int.from_bytes(
            bt[lfanew + (0x84 if self.magic == b"\x0b\x01" else 0xa4):
               lfanew + (0x88 if self.magic == b"\x0b\x01" else 0xa8)], "little"), 0x14):
            if bt[import_seg_addr:import_seg_addr + 0x14] == b"\x00" * 20:
                break
            import_seg_indexes = []
            import_seg_names = []
            import_seg_pos = self.foa(int.from_bytes(bt[import_seg_addr:import_seg_addr + 
                                                        (4 if self.magic == b"\x0b\x01" else 8)], "little"))
            while True:
                import_seg_high, import_seg_low = divmod(
                    int.from_bytes(bt[import_seg_pos:import_seg_pos + (4 if self.magic == b"\x0b\x01" else 8)], "little"), 
                    2 ** (15 if self.magic == b"\x0b\x01" else 31))
                if import_seg_high == 0 and import_seg_low == 0:
                    break
                if import_seg_high:
                    import_seg_indexes.append(import_seg_low)
                else:
                    import_seg_names.append(_get_name(bt, self.foa(import_seg_low) + 2))
                import_seg_pos += 4 if self.magic == b"\x0b\x01" else 8
            self.import_tb.append({
                "indexes": import_seg_indexes, "names": import_seg_names, "name": 
                _get_name(bt, self.foa(int.from_bytes(bt[import_seg_addr + (0x0c if self.magic == b"\x0b\x01" else 0x18):
                                                         import_seg_addr + (0x10 if self.magic == b"\x0b\x01" else 0x1c)], 
                                                         "little")))
            })
        #导出表
        export_tb_addr = self.foa(int.from_bytes(
            bt[lfanew + (0x78 if self.magic == b"\x0b\x01" else 0x98):lfanew + 
               (0x7c if self.magic == b"\x0b\x01" else 0x9c)], "little"))
        if(int.from_bytes(bt[lfanew + 
                             (0x7c if self.magic == b"\x0b\x01" else 0x9c):lfanew + 
                             (0x80 if self.magic == b"\x0b\x01" else 0xa0)], "little") >= 40):
            export_tb_funcs_addr = self.foa(int.from_bytes(bt[export_tb_addr + 28:export_tb_addr + 32], "little"))
            self.export_tb_funcs = [
                int.from_bytes(bt[export_seg_addr:export_seg_addr + 4], "little") 
                    for export_seg_addr in range(export_tb_funcs_addr, export_tb_funcs_addr + 4 * int.from_bytes(
                                                   bt[export_tb_addr + 20:export_tb_addr + 24], "little"
                                               ), 4)]
            export_tb_names_addr = self.foa(int.from_bytes(bt[export_tb_addr + 32:export_tb_addr + 36], "little"))
            export_tb_names_size = int.from_bytes(bt[export_tb_addr + 24:export_tb_addr + 28], "little")
            self.export_tb_names = [
                _get_name(bt, self.foa(int.from_bytes(bt[export_seg_addr:export_seg_addr + 4], "little"))) 
                for export_seg_addr in range(export_tb_names_addr, export_tb_names_addr + 4 * export_tb_names_size, 4)
            ]
            export_tb_ord_names_addr = self.foa(int.from_bytes(bt[export_tb_addr + 36:export_tb_addr + 40], "little"))
            self.export_tb_ord_names = [
                int.from_bytes(bt[export_seg_addr:export_seg_addr + 2], "little") for export_seg_addr in range(
                    export_tb_ord_names_addr, export_tb_ord_names_addr + export_tb_names_size * 2, 2
                )
            ]
            self.export_tb_base = int.from_bytes(bt[export_tb_addr + 16:export_tb_addr + 20], "little")
            self.export_tb_name = _get_name(bt, self.foa(int.from_bytes(bt[export_tb_addr + 12:export_tb_addr + 16]
                                                                    , "little")))
        else:
            self.export_tb_funcs, self.export_tb_names, self.export_tb_ord_names = [], [], []
        #重定位表
        rel_addr_pos = self.foa(int.from_bytes(bt[lfanew + 0xa0:lfanew + 0xa4], "little"))
        rel_addr_base_pos = rel_addr_pos
        rel_addr_size = int.from_bytes(bt[lfanew + 0xa4:lfanew + 0xa8], "little")
        self.rel_tb = []
        while True:
            if rel_addr_pos - rel_addr_base_pos >= rel_addr_size:
                break
            rel_addr_base = int.from_bytes(bt[rel_addr_pos:rel_addr_pos + 4], "little")
            rel_addr_pos += 8
            rel_addr_temp = []
            for rel_addr_pos in range(rel_addr_pos, rel_addr_pos + 
                                      int.from_bytes(bt[rel_addr_pos - 4:rel_addr_pos], "little") - 8, 2):
                rel_var_high, rel_var_low = divmod(int.from_bytes(bt[rel_addr_pos:rel_addr_pos + 2], "little"), 2 ** 12)
                if rel_var_high == 3:
                    rel_addr_temp.append(rel_var_low)
            self.rel_tb.append({
                "base": rel_addr_base, "addr": rel_addr_temp
            })
    
    def foa(self, rva: int):
        """RVA转换成FOA"""
        for sec in self.secs:
            if rva >= sec["virsual_addr"] and rva < sec["virsual_addr"] + sec["virsual_size"]:
                return rva + sec["file_addr"] - sec["virsual_addr"]
        if rva < self.lfanew + (0xf8 if self.magic == b"\x0b\x01" else 0x108):
            return rva
        raise ValueError("Not found.")
    
    def rva(self, foa: int):
        """FOA转换成RVA"""
        for sec in self.secs:
            r = foa + sec["virsual_addr"] - sec["file_addr"]
            if r >= sec["virsual_addr"] and r < sec["virsual_addr"] + sec["virsual_size"]:
                return r
        if foa < self.lfanew + (0xf8 if self.magic == b"\x0b\x01" else 0x108):
            return foa
        raise ValueError("Not found.")
