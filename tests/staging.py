"""Preserve private-test context in the owned physical-copy wire harnesses."""
from pathlib import Path
import shutil
import subprocess


def test_files(package):
    package = Path(package)
    return sorted([*package.glob('*.odin'), *package.glob('tests/internal/*.odin')])


def copy_closure(gate, package, source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    pending, copied = [package], set()
    while pending:
        modules = gate.copy_closure(pending.pop(), source, destination)
        for module in modules:
            if module in copied:
                continue
            copied.add(module)
            current = source / module
            tests = current / 'tests'
            if tests.is_dir():
                shutil.copytree(tests, destination / module / 'tests', dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            # These imports and loads are relative to the production package,
            # where the private files are restored only while compiling tests.
            for file in current.glob('tests/internal/*.odin'):
                text = file.read_text()
                for imported in gate.IMPORT.findall(text):
                    if imported.startswith('shared:'):
                        dependency = source / imported[len('shared:'):]
                    elif ':' not in imported:
                        dependency = current / imported
                    else:
                        continue
                    name = str(dependency.resolve().relative_to(source))
                    if name not in copied:
                        pending.append(name)
                for loaded in gate.LOAD.findall(text):
                    resource = (current / loaded).resolve()
                    target = destination / resource.relative_to(source)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(resource, target)
    return sorted(copied)


def test_run(command, **kwargs):
    """Stage private files in an owned copy, then restore it even on failure."""
    created = []
    args = list(map(str, command))
    try:
        if len(args) > 2 and args[1] == 'test':
            collection = next((a.split('=', 1)[1] for a in args
                               if a.startswith('-collection:shared=')), None)
            if collection is None:
                raise ValueError('Private test staging requires an explicit shared copy')
            shared = Path(collection).resolve()
            if (shared / '.git').exists() or any(
                    (child / '.git').exists() for child in shared.iterdir() if child.is_dir()):
                raise ValueError('Private test staging cannot modify a Git checkout')
            for library in shared.iterdir():
                if not library.is_dir() or library.name.startswith('.'):
                    continue
                for source in sorted(library.glob('**/tests/internal/*.odin')):
                    if any(part.startswith('.') for part in source.relative_to(shared).parts):
                        continue
                    target = source.parent.parent.parent / source.name
                    if target.exists():
                        if target.read_bytes() != source.read_bytes():
                            raise ValueError('Conflicting private test overlay: ' + str(target))
                        continue
                    shutil.copy2(source, target)
                    created.append(target)
        return subprocess.run(command, **kwargs)
    finally:
        for target in reversed(created):
            target.unlink()
