import subprocess
import os

os.chdir(r'C:\Users\BLy\Desktop\900\Dynam-main')

# Удаляем временные файлы
for f in ['check_git.py', 'git_push.py', 'git_status.txt']:
    if os.path.exists(f):
        os.remove(f)
        print(f"Removed {f}")

# Обновляем .gitignore - добавляем build и временные файлы
gitignore_content = """# Build directories
build/
*/build/
*/*/build/
*/*/*/build/

# IDE
.vs/
.vscode/
.idea/
*.suo
*.user
*.userosscache
*.sln.docstates

# Temporary files
*.tmp
*.log
check_git.py
git_push.py
git_status.txt

# Python
__pycache__/
*.pyc
*.pyo

# OS
Thumbs.db
.DS_Store
"""

with open('.gitignore', 'w') as f:
    f.write(gitignore_content)

# Добавляем все файлы заново
result = subprocess.run(['git', 'add', '.'], capture_output=True, text=True)
print("add:", result.returncode)

# Коммит
result = subprocess.run(['git', 'commit', '-m', 'Initial commit: Dynam project full source'], capture_output=True, text=True)
print("COMMIT:", result.stdout, result.stderr)

# Пуш
print("Pushing to GitHub...")
result = subprocess.run(['git', 'push', '-u', 'origin', 'master'], capture_output=True, text=True)
print("PUSH:", result.stdout, result.stderr)
print("Return code:", result.returncode)
