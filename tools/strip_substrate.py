#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
strip_substrate.py —— 清掉 iOS dylib 里的越狱 / 注入指纹

处理两类 Mach-O 命令：
  1) LC_LOAD_*_DYLIB 里指向 CydiaSubstrate / libsubstrate 的依赖
  2) LC_ID_DYLIB 里 Theos 默认的
     /Library/MobileSubstrate/DynamicLibraries/<name>.dylib（改成 @rpath 形式）

为什么不是「删掉那条 LC_LOAD_DYLIB」：
    dylib 的符号绑定表（__DATA 里 lazy / non-lazy symbol pointers）是按
    LC_LOAD_DYLIB 的**出现顺序**编号（ordinal）来引用库的。删掉中间一条，
    后面所有库的序号都会前移，绑定表全部错位 → dyld 加载即崩。
    所以这里只把该命令里的 name 字符串原地换成无害的系统库名，
    ncmds / sizeofcmds / 所有段偏移 / ordinal 全部保持不变。

前提：
    源码已经不调用 MSHookMessageEx / MSHookFunction 等 Substrate 符号。
    脚本会扫描残留，若发现仍引用则直接失败，避免产出「能装但必崩」的包。

用法：
    python3 tools/strip_substrate.py <file.dylib>              # 原地处理 + 报告
    python3 tools/strip_substrate.py <file.dylib> -o out.dylib  # 另存
    python3 tools/strip_substrate.py <file.dylib> --report      # 只读列依赖
"""
import argparse
import os
import struct
import sys

# 目标：宿主反作弊扫的就是这些名字
SAFE_NAME = b"/usr/lib/libobjc.A.dylib"

LC_ID_DYLIB          = 0x0000000d
LC_LOAD_DYLIB        = 0x0000000c
LC_LOAD_WEAK_DYLIB   = 0x80000018
LC_REEXPORT_DYLIB    = 0x8000001f
LC_LAZY_LOAD_DYLIB   = 0x00000020
LC_LOAD_UPWARD_DYLIB = 0x80000023
DYLIB_CMDS = {
    LC_ID_DYLIB, LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB,
    LC_LAZY_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB,
}
CMD_NAMES = {
    LC_ID_DYLIB: "ID_DYLIB", LC_LOAD_DYLIB: "LOAD_DYLIB",
    LC_LOAD_WEAK_DYLIB: "LOAD_WEAK_DYLIB", LC_REEXPORT_DYLIB: "REEXPORT_DYLIB",
    LC_LAZY_LOAD_DYLIB: "LAZY_LOAD_DYLIB",
    LC_LOAD_UPWARD_DYLIB: "LOAD_UPWARD_DYLIB",
}

# Theos 给 tweak 设置的默认 install name 是
#   /Library/MobileSubstrate/DynamicLibraries/<name>.dylib
# 这条字符串本身就带 MobileSubstrate / DynamicLibraries 两个越狱关键词，
# 必须一起改成正常的 @rpath 形式。
ID_PATH_MARKERS = (b"mobilesubstrate", b"dynamiclibraries", b"cydiasubstrate")

# 如果二进制里还残留这些，说明源码仍在用 Substrate，替换后必然崩
FATAL_RESIDUES = (b"MSHookMessageEx", b"MSHookFunction", b"MSHookClassPair", b"_logos_")
# 这些是宿主 dyld 镜像扫描最容易认的越狱关键词，成品里必须一个都不剩
SOFT_RESIDUES  = (b"CydiaSubstrate", b"libsubstrate", b"MobileSubstrate",
                  b"DynamicLibraries", b"/Library/Frameworks/CydiaSubstrate")


def thin_kind(raw4):
    if raw4 == b"\xcf\xfa\xed\xfe":
        return "<", True          # MH_MAGIC_64，小端 64 位（iOS arm64）
    if raw4 == b"\xfe\xed\xfa\xcf":
        return ">", True          # MH_CIGAM_64
    if raw4 == b"\xce\xfa\xed\xfe":
        return "<", False         # MH_MAGIC，小端 32 位
    if raw4 == b"\xfe\xed\xfa\xce":
        return ">", False         # MH_CIGAM
    return None, None


def process_thin(buf, off, label, do_write, id_name=None):
    """处理一个 thin Mach-O slice，返回 (依赖清单, 替换数)。"""
    endian, is64 = thin_kind(bytes(buf[off:off + 4]))
    if endian is None:
        raise ValueError("%s: 不是 Mach-O slice (magic=%s)" % (label, buf[off:off + 4].hex()))

    hdr_size = 32 if is64 else 28
    cputype = struct.unpack_from(endian + "i", buf, off + 4)[0]
    ncmds = struct.unpack_from(endian + "I", buf, off + 16)[0]
    sizeofcmds = struct.unpack_from(endian + "I", buf, off + 20)[0]
    print("  [%s] magic=%s cputype=0x%x ncmds=%d sizeofcmds=%d" %
          (label, bytes(buf[off:off + 4]).hex(), cputype & 0xffffffff, ncmds, sizeofcmds))

    deps, changed = [], 0
    pos = off + hdr_size
    end_cmds = pos + sizeofcmds
    if end_cmds > len(buf):
        raise ValueError("%s: sizeofcmds 越界" % label)

    for _ in range(ncmds):
        if pos + 8 > end_cmds:
            raise ValueError("%s: load command 截断" % label)
        cmd, cmdsize = struct.unpack_from(endian + "II", buf, pos)
        if cmdsize < 8 or pos + cmdsize > end_cmds:
            raise ValueError("%s: 非法 cmdsize=%d" % (label, cmdsize))

        if cmd in DYLIB_CMDS and cmdsize >= 24:
            name_off = struct.unpack_from(endian + "I", buf, pos + 8)[0]
            name_start = pos + name_off
            name_end = pos + cmdsize
            if 8 <= name_off < cmdsize and name_start < name_end <= len(buf):
                raw = bytes(buf[name_start:name_end])
                name = raw.split(b"\x00", 1)[0]
                deps.append((CMD_NAMES.get(cmd, hex(cmd)), name.decode("utf-8", "replace")))
                low = name.lower()
                replacement = None

                if cmd == LC_ID_DYLIB and any(m in low for m in ID_PATH_MARKERS):
                    # install name：越狱 tweak 路径 -> 正常的 @rpath 形式。
                    # --id-name 指定时用指定 basename（配合带版本号的交付文件名，
                    # 让 ID 与文件名一致且不含旧工程前缀），否则沿用原 ID 的 basename
                    base = (id_name.encode("utf-8") if id_name
                            else (name.split(b"/")[-1] or b"ACEntry.dylib"))
                    replacement = b"@rpath/" + base + b"\x00"
                elif cmd != LC_ID_DYLIB and b"substrate" in low:
                    # 依赖：换成无害系统库，保持 ordinal 不变
                    replacement = SAFE_NAME + b"\x00"

                if replacement:
                    print("  [命中] %s -> %s" %
                          (name.decode("utf-8", "replace"),
                           replacement[:-1].decode("utf-8", "replace")))
                    if do_write:
                        if len(replacement) > name_end - name_start:
                            raise ValueError("%s: 新名字放不下，放弃替换" % label)
                        buf[name_start:name_end] = replacement + b"\x00" * (
                            name_end - name_start - len(replacement))
                        # 若原本是 reexport / lazy / upward，降级成普通 LOAD_DYLIB，
                        # 避免重复导出 libobjc 符号或改变加载语义
                        if cmd in (LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB):
                            struct.pack_into(endian + "I", buf, pos, LC_LOAD_DYLIB)
                    changed += 1
        pos += cmdsize
    return deps, changed


def fat_slices(buf):
    """返回 [(label, offset, is64_arch)]；非 FAT 返回 None。"""
    raw4 = bytes(buf[:4])
    if raw4 not in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        return None
    arch64 = raw4 == b"\xca\xfe\xba\xbf"
    nfat = struct.unpack_from(">I", buf, 4)[0]
    out = []
    p = 8
    step = 32 if arch64 else 20
    for i in range(nfat):
        cputype = struct.unpack_from(">i", buf, p)[0]
        if arch64:
            offset = struct.unpack_from(">Q", buf, p + 8)[0]
        else:
            offset = struct.unpack_from(">I", buf, p + 8)[0]
        out.append(("arch%d-cpu0x%x" % (i, cputype & 0xffffffff), offset))
        p += step
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--id-name", default=None,
                    help="install name 的 basename；默认沿用原 ID 的 basename")
    ap.add_argument("--report", action="store_true", help="只读，列出依赖不修改")
    args = ap.parse_args()

    with open(args.path, "rb") as f:
        buf = bytearray(f.read())
    print("文件: %s (%d 字节)" % (os.path.basename(args.path), len(buf)))

    if not args.report:
        for r in FATAL_RESIDUES:
            if r in buf:
                print("[FATAL] 仍残留 Substrate 符号 %s —— 源码还没去干净，替换后必崩，终止。" %
                      r.decode(), file=sys.stderr)
                return 2
    else:
        for r in FATAL_RESIDUES:
            if r in buf:
                print("[报告] 发现 Substrate 符号残留: %s" % r.decode())

    slices = fat_slices(buf)
    if slices:
        print("FAT 文件，%d 个架构" % len(slices))
        targets = [(lbl, off) for lbl, off in slices]
    else:
        targets = [("thin", 0)]

    all_deps, total = [], 0
    for lbl, off in targets:
        deps, n = process_thin(buf, off, lbl, not args.report, args.id_name)
        all_deps.extend(deps)
        total += n

    print("依赖清单 (%d 条):" % len(all_deps))
    for kind, name in all_deps:
        print("    %-18s %s" % (kind, name))
    print("Substrate 依赖替换数: %d" % total)

    if not args.report:
        left = [r.decode() for r in SOFT_RESIDUES if r in buf]
        dest = args.output or args.path
        with open(dest, "wb") as f:
            f.write(buf)
        print("已写出: %s" % dest)
        if left:
            print("[FATAL] 成品里仍残留越狱关键词: %s" % ", ".join(left), file=sys.stderr)
            return 3
        print("[OK] 越狱关键词字节级扫描：零残留")
    return 0


if __name__ == "__main__":
    sys.exit(main())
