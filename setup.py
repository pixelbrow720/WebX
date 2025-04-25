from setuptools import setup, find_packages

with open("dependency-list.txt") as f:
    requirements = [line.strip() for line in f.readlines() if not line.startswith("#")]

setup(
    name="web-security-recon-tool",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    python_requires=">=3.11",
    author="Replit User",
    description="AI-Powered Web Security Reconnaissance Tool",
    keywords="security, web, reconnaissance, vulnerability, scanning",
    project_urls={
        "Source Code": "https://github.com/yourusername/web-security-recon-tool",
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
    ],
)