import zipfile
import os

root = os.getcwd()
zip_path = os.path.join(root, 'code.zip')

# Files and directories to include
INCLUDE_FILES = [
    'code/main.py',
    'evaluation/evaluation_report.md',
    'evaluation/usage_report.md',
    'README.md',
    'AGENTS.md',
    'CLAUDE.md',
    'agent_trace_instructions.md',
    'problem_statement.md',
    'log.txt',
]

# Scratch scripts are informational only - exclude from submission zip per §6.8
EXCLUDE_PREFIXES = ('scratch_', '__pycache__', '.git', 'dataset/', '.env')

with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
    for rel_path in INCLUDE_FILES:
        full = os.path.join(root, rel_path)
        if os.path.exists(full):
            zf.write(full, rel_path)
            print(f'  Added: {rel_path}')
        else:
            print(f'  MISSING: {rel_path}')

print(f'\ncode.zip created: {zip_path}')
print(f'Size: {os.path.getsize(zip_path):,} bytes')

# List contents
with zipfile.ZipFile(zip_path, 'r') as zf:
    print('\nContents:')
    for info in zf.infolist():
        print(f'  {info.filename} ({info.file_size:,} bytes)')
