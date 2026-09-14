#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""知识库一致性检查（防漂移）

检查内容：
1. AI-MAP.json 登记的文档是否真实存在（防改名/误删后映射失效）
2. 磁盘上的 .md 文档是否都已登记进 AI-MAP.json（防新增后漏登记）
3. 索引文件中的文档链接/路径引用是否能解析到真实文件（防死链）
4. frontmatter 覆盖率（观察项，不计入失败）

用法:
    python scripts/check-consistency.py
退出码: 0 通过, 1 发现问题（可直接接入 GitHub Actions / pre-commit）
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAP_FILE = ROOT / "AI-MAP.json"
# 需要提取链接引用的索引文件
LINK_SOURCES = [
    "README.md",
    "AGENTS.md",
    "AI-WIKI.md",
    "penetration/README.md",
    "exp/EXP-Vul-Index.md",
]

problems = []
infos = []


def main():
    # ---------- 1/2: AI-MAP.json 与磁盘双向核对 ----------
    data = json.loads(MAP_FILE.read_text(encoding="utf-8-sig"))
    mapped = {d["path"].replace("\\", "/") for d in data.get("docs", [])}
    topic_docs = {p.replace("\\", "/") for t in data.get("topics", []) for p in t.get("docs", [])}

    all_md = {str(p.relative_to(ROOT)).replace("\\", "/") for p in ROOT.rglob("*.md")}

    for p in sorted(mapped | topic_docs):
        if not (ROOT / p).is_file():
            problems.append("[映射失效] AI-MAP.json 登记的文件不存在: " + p)

    for p in sorted(all_md - mapped):
        problems.append("[漏登记] 未收录进 AI-MAP.json: " + p)

    # ---------- 3: 索引文件中的链接检查 ----------
    # 形式1: [text](./path.md)，锚点(#)与外链自动跳过
    md_link_re = re.compile(r"\]\((\.{1,2}/[^)\s#]+\.md)\)")
    # 形式2: 反引号路径 `./path.md`（AI-WIKI 映射表大量使用）
    tick_path_re = re.compile(r"`(\.{1,2}/[^`\s]+\.md)`")

    for src in LINK_SOURCES:
        f = ROOT / src
        if not f.is_file():
            problems.append("[缺索引] 约定的索引文件不存在: " + src)
            continue
        text = f.read_text(encoding="utf-8-sig")
        refs = set(md_link_re.findall(text)) | set(tick_path_re.findall(text))
        for ref in sorted(refs):
            resolved = (f.parent / ref).resolve()
            if not resolved.is_file():
                problems.append("[死链] {} -> {}".format(src, ref))

    # ---------- 4: frontmatter 覆盖率（观察项） ----------
    # 豁免：公开 README 与 AGENTS 规则文件不加 frontmatter
    fm_exempt = {"README.md", "AGENTS.md"}
    fm_total = 0
    fm_count = 0
    for p in all_md:
        if p in fm_exempt:
            continue
        fm_total += 1
        head = (ROOT / p).read_text(encoding="utf-8-sig", errors="ignore")[:200]
        if head.startswith("---") and re.search(r"^title:", head, re.M):
            fm_count += 1
    if fm_total:
        infos.append("frontmatter 覆盖率: {}/{} ({}%)".format(
            fm_count, fm_total, round(fm_count * 100 / fm_total)))

    # ---------- 输出 ----------
    print("=" * 50)
    print("知识库一致性检查")
    print("文档总数: {} | 主题映射: {} 组".format(len(all_md), len(data.get("topics", []))))
    for i in infos:
        print("[INFO] " + i)
    if problems:
        print("-" * 50)
        for p in problems:
            print("[FAIL] " + p)
        print("-" * 50)
        print("共 {} 个问题，请修复后重试".format(len(problems)))
        sys.exit(1)
    print("[OK] 全部通过")
    sys.exit(0)


if __name__ == "__main__":
    main()
