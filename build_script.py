# build_script.py
import PyInstaller.__main__
import sys

PyInstaller.__main__.run([
    'phishing_scanner.py',  # your main script
    '--onefile',           # create a single executable
    '--noconsole',        # don't show console window
    '--name=PhishingScanner',
    '--add-data=README.md;.',  # Add any additional data files
    '--icon=icon.ico',    # Optional: Add an icon
    '--clean',            # Clean PyInstaller cache
    '--windowed',         # Windows only
])