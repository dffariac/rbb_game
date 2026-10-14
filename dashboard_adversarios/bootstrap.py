import importlib.util
import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent

PACKAGES = {
    "streamlit": "streamlit>=1.40,<2",
    "pandas": "pandas>=2.1,<3",
    "plotly": "plotly>=5.20,<7",
    "openpyxl": "openpyxl>=3.1,<4",
}


missing_packages = []

for module_name, package_name in PACKAGES.items():
    if importlib.util.find_spec(module_name) is None:
        missing_packages.append(package_name)


if missing_packages:
    print("Instalando dependências...")
    subprocess.check_call(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            *missing_packages,
        ]
    )


print("Iniciando o Streamlit...")

subprocess.check_call(
    [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(ROOT_DIR / "app.py"),
    ],
    cwd=ROOT_DIR,
)