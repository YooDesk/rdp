"""从固定IronRDP源码构建浏览器WASM；隔离FFI工具链，不修改参考源码或产品名称。"""
import argparse
import hashlib
import io
import tarfile
import tempfile
import json
import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]
COMMIT = '11a0810cfbbabd8b8023875a05e3041216d4b01b'
BINDGEN = '0.2.126'
SOURCE_SHA256 = '1210732fa81cfe7c92493b8d7dcde6a59503fc1b26d1134f0bb60780af6ea3c5'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, help='optional verified source archive directory')
    parser.add_argument('--wasm-bindgen', type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temp:
        if args.source is None:
            submodule = ROOT / 'deps/ironrdp'
            revision = subprocess.check_output(['git', '-C', str(submodule), 'rev-parse', 'HEAD'], text=True).strip()
            if revision != COMMIT:
                raise RuntimeError('Initialize the pinned IronRDP submodule first')
            data = subprocess.check_output(['git', '-C', str(submodule), 'archive', COMMIT])
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                archive.extractall(temp, filter='data')
        build_client(args, args.source.resolve(strict=True) if args.source else Path(temp))


def build_client(args, source):

    digest = hashlib.sha256()
    # The existing digest was produced with WindowsPath's case-insensitive component ordering.
    # Make that ordering explicit so the same pinned archive verifies on the Linux builder.
    for path in sorted(source.rglob('*'), key=lambda value: tuple(part.casefold() for part in value.relative_to(source).parts)):
        if path.is_file():
            digest.update(path.relative_to(source).as_posix().encode() + b'\0' + path.read_bytes() + b'\0')
    if digest.hexdigest() != SOURCE_SHA256:
        raise RuntimeError('Source must be the unmodified official archive for ' + COMMIT)
    build = ROOT / 'artifacts/ironrdp-web-build'
    if not (build / 'Cargo.toml').is_file():
        shutil.copytree(source, build, ignore=shutil.ignore_patterns('.git', 'target', 'node_modules'), dirs_exist_ok=True)
        manifest = build / 'Cargo.toml'
        text = manifest.read_text(encoding='utf-8')
        start = text.index('members = [')
        end = text.index(']', start) + 1
        text = text[:start] + 'members = ["crates/ironrdp-web"]' + text[end:]
        # Diplomat补丁只用于本轮不构建的FFI；浏览器构建无需检出额外Git工具链。
        text = text[:text.index('[patch.crates-io]')]
        manifest.write_text(text, encoding='utf-8', newline='\n')
    # 仅修改隔离构建副本；逐文件核对固定上游源码或可重现的本地音频补丁。
    patches_to_apply = [ROOT / 'patches' / name for name in ('ironrdp-audio.patch', 'ironrdp-clipboard.patch')]
    if not (build / '.git').exists():
        subprocess.run(['git', 'init', '-q'], cwd=build, check=True)
    for patch in patches_to_apply:
        patch_data = patch.read_text(encoding='utf-8').encode('utf-8')
        if subprocess.run(['git', 'apply', '--reverse', '--check', '-'], cwd=build, input=patch_data, capture_output=True).returncode:
            subprocess.run(['git', 'apply', '-'], cwd=build, input=patch_data, check=True)
    lock = ROOT / 'scripts/rdp-client-Cargo.lock'
    if lock.exists():
        shutil.copyfile(lock, build / 'Cargo.lock')
    env = os.environ.copy()
    env.setdefault('RUSTUP_TOOLCHAIN', '1.99.0')
    command = ['cargo', 'build', '-p', 'ironrdp-web', '--target', 'wasm32-unknown-unknown', '--profile', 'production-wasm']
    if lock.exists():
        command.append('--locked')
    subprocess.run(command, cwd=build, env=env, check=True)
    shutil.copyfile(build / 'Cargo.lock', lock)
    tool = args.wasm_bindgen.resolve(strict=True)
    version = subprocess.check_output([str(tool), '--version'], text=True).strip()
    if version != f'wasm-bindgen {BINDGEN}':
        raise RuntimeError(f'Expected wasm-bindgen {BINDGEN}, got {version}')
    output = ROOT / 'assets/ironrdp'
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(tool), str(build / 'target/wasm32-unknown-unknown/production-wasm/ironrdp_web.wasm'), '--target', 'web', '--out-dir', str(output), '--out-name', 'ironrdp'], check=True)
    for name in ['LICENSE-MIT', 'LICENSE-APACHE']:
        shutil.copyfile(source / name, output / name)
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir() if p.is_file() and p.name != 'source.json'}
    rustc = subprocess.check_output(['rustc', '--version'], text=True, env=env).strip()
    patches = {patch.name: hashlib.sha256(patch.read_text(encoding='utf-8').encode('utf-8')).hexdigest() for patch in patches_to_apply}
    (output / 'source.json').write_text(json.dumps({'upstream': 'https://github.com/Devolutions/IronRDP', 'commit': COMMIT, 'source_tree_sha256': SOURCE_SHA256, 'rustc': rustc, 'wasm_bindgen': BINDGEN, 'workspace_adaptation': 'only browser member; omit FFI-only Diplomat patch; YooDesk RDPSND PCM adapter and CLIPRDR read sequencing', 'patches': patches, 'files': files}, indent=2)+'\n', encoding='utf-8')
    print('Built IronRDP browser client from', COMMIT)


if __name__ == '__main__':
    main()
