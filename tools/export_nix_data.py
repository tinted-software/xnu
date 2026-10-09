#!/usr/bin/env python3
"""Export static sources and job lists to .nix files."""

import json
import subprocess
from pathlib import Path
from tools.pcons.mig import MIG_JOBS, plan_mig_job
from tools.pcons.iig import IIG_NAMES, plan_iig_job
from tools.pcons.iostorage import iostorage_sources

def nix_str_list(lst, indent=4):
    pad = " " * indent
    lines = ["["]
    for x in lst:
        lines.append(f'{pad}  "{x}"')
    lines.append(f"{pad}]")
    return "\n".join(lines)

def export_components():
    out = subprocess.check_output(['python3', 'tools/pcons/xnu_config.py', '--srcroot', '.', '--kernel-config', 'DEVELOPMENT', '--format', 'json'])
    data = json.loads(out)
    
    for comp, files in data['components'].items():
        c_files = [f for f in files.get('c', []) if '/Tests/' not in f]
        cpp_files = [f for f in files.get('cpp', []) if '/Tests/' not in f]
        s_files = [f for f in files.get('s', []) if '/Tests/' not in f]
        
        comp_dir = Path(comp)
        comp_dir.mkdir(parents=True, exist_ok=True)
        sources_nix = comp_dir / "sources.nix"
        
        content = f"""# Source list for {comp}
{{
  c = {nix_str_list(c_files, 2)};
  cpp = {nix_str_list(cpp_files, 2)};
  s = {nix_str_list(s_files, 2)};
}}
"""
        sources_nix.write_text(content)
        print(f"Wrote {sources_nix}")

def find_vendor_dir(name, marker):
    local_path = Path(f"external/{name}")
    if local_path.exists():
        return local_path
    cache_dir = Path.home() / ".cache" / "rix" / "git"
    if cache_dir.exists():
        for d in cache_dir.iterdir():
            if d.is_dir() and (d / marker).exists():
                return d
    return local_path


def export_iostorage():
    ios_dir = find_vendor_dir("IOStorageFamily", "IOStorage.cpp")
    srcs_raw = iostorage_sources(ios_dir)
    prefix = str(ios_dir) + "/"
    srcs = []
    for f in srcs_raw:
        if f.startswith(prefix):
            srcs.append(f[len(prefix):])
        elif f.startswith("external/IOStorageFamily/"):
            srcs.append(f[len("external/IOStorageFamily/"):])
        else:
            srcs.append(f)
            
    Path("nix/components").mkdir(parents=True, exist_ok=True)
    sources_nix = Path("nix/components/iostorage-sources.nix")
    content = f"""# Source list for IOStorageFamily
{{
  srcs = {nix_str_list(srcs, 2)};
}}
"""
    sources_nix.write_text(content)
    print(f"Wrote {sources_nix}")

def export_mig():
    jobs = []
    for job in MIG_JOBS:
        p = plan_mig_job(job, "build/mig")
        jobs.append({
            "name": job.out,
            "defsFile": p.defs_file,
            "outDir": p.out_dir,
            "subDir": p.sub_dir,
            "stem": p.stem,
            "extraFlags": p.extra_flags,
            "outputs": p.outputs,
            "cFile": p.c_file,
        })
    
    lines = ["# Auto-generated MIG job descriptions", "["]
    for j in jobs:
        lines.append("  {")
        lines.append(f'    name = "{j["name"]}";')
        lines.append(f'    defsFile = "{j["defsFile"]}";')
        lines.append(f'    outDir = "{j["outDir"]}";')
        lines.append(f'    subDir = "{j["subDir"]}";')
        lines.append(f'    stem = "{j["stem"]}";')
        lines.append(f'    extraFlags = {nix_str_list(j["extraFlags"], 4)};')
        lines.append(f'    outputs = {nix_str_list(j["outputs"], 4)};')
        lines.append(f'    cFile = "{j["cFile"]}";')
        lines.append("  }")
    lines.append("]")
    
    Path("nix/codegen").mkdir(parents=True, exist_ok=True)
    out_file = Path("nix/codegen/mig-jobs.nix")
    out_file.write_text("\n".join(lines) + "\n")
    print(f"Wrote {out_file}")

def export_iig():
    jobs = []
    for name in IIG_NAMES:
        p = plan_iig_job(name, "build/iig")
        jobs.append({
            "name": name,
            "defFile": p.def_file,
            "outDir": p.out_dir,
            "headerOut": p.header_out,
            "cppOut": p.cpp_out,
        })
    
    lines = ["# Auto-generated IIG job descriptions", "["]
    for j in jobs:
        lines.append("  {")
        lines.append(f'    name = "{j["name"]}";')
        lines.append(f'    defFile = "{j["defFile"]}";')
        lines.append(f'    outDir = "{j["outDir"]}";')
        lines.append(f'    headerOut = "{j["headerOut"]}";')
        lines.append(f'    cppOut = "{j["cppOut"]}";')
        lines.append("  }")
    lines.append("]")
    
    out_file = Path("nix/codegen/iig-jobs.nix")
    out_file.write_text("\n".join(lines) + "\n")
    print(f"Wrote {out_file}")

if __name__ == "__main__":
    export_components()
    export_iostorage()
    export_mig()
    export_iig()
