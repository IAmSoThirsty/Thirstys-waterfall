"""
Thirstys Waterfall Setup
Evidence-gated integrated privacy-first system
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="thirstys-waterfall",
    version="1.0.2",
    author="Thirsty Security Team",
    author_email="security@thirstys.local",
    description="Integrated privacy-first system with 8 firewalls, built-in VPN, and incognito browser",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/IAmSoThirsty/Thirstys-waterfall",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: Browsers",
        "Topic :: System :: Networking :: Firewalls",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.10",
    install_requires=[
        "cryptography>=46.0.7,<50.0.0",
    ],
    entry_points={
        "console_scripts": [
            "thirstys-waterfall=thirstys_waterfall.cli:main",
        ],
    },
)
