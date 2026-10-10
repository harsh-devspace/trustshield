"""
TrustShield Extension Packaging Script
Creates a clean, distributable ZIP containing the Manifest V3 Chrome Extension.
Ensures manifest.json is directly at the root of the ZIP file.
"""

import os
import zipfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
EXTENSION_DIR = BASE_DIR / "extension"
OUTPUT_ZIP = BASE_DIR / "trustshield-extension.zip"
STATIC_ZIP = EXTENSION_DIR / "trustshield-extension.zip"

EXCLUDE_EXTENSIONS = {".pyc", ".pyo", ".git", ".DS_Store", ".tmp", ".zip"}
EXCLUDE_DIRS = {"__pycache__", ".git", "venv", ".pytest_cache", "node_modules"}

def package_extension():
    print(f"[TrustShield] Packaging extension from: {EXTENSION_DIR}")
    if not (EXTENSION_DIR / "manifest.json").exists():
        raise FileNotFoundError(f"manifest.json missing in {EXTENSION_DIR}")

    files_added = []
    
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(EXTENSION_DIR):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            
            for file in files:
                if any(file.endswith(ext) for ext in EXCLUDE_EXTENSIONS):
                    continue
                file_path = Path(root) / file
                arcname = file_path.relative_to(EXTENSION_DIR)
                zf.write(file_path, arcname)
                files_added.append(str(arcname))

    # Also copy to extension/ so relative link in trust.html works offline
    import shutil
    shutil.copy2(OUTPUT_ZIP, STATIC_ZIP)

    print(f"[TrustShield] Created distributable archive: {OUTPUT_ZIP} ({OUTPUT_ZIP.stat().st_size} bytes)")
    print(f"[TrustShield] Copied archive for static access to: {STATIC_ZIP}")
    print(f"[TrustShield] Total files included: {len(files_added)}")
    assert "manifest.json" in files_added, "manifest.json must be at ZIP root!"
    return OUTPUT_ZIP

if __name__ == "__main__":
    package_extension()
