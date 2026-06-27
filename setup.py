"""WebAudit package setup."""

from setuptools import setup, find_packages

setup(
    name="webaudit",
    version="1.0.0",
    description="Professional Web Application Auditing Tool",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="WebAudit Team",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "aiohttp>=3.9.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=5.1.0",
        "cssutils>=2.9.0",
        "playwright>=1.40.0",
        "Pillow>=10.2.0",
        "Jinja2>=3.1.0",
        "fpdf2>=2.7.0",
        "rich>=13.7.0",
        "colorama>=0.4.6",
        "pydantic>=2.5.0",
        "PyJWT>=2.8.0",
        "SQLAlchemy>=2.0.0",
        "psutil>=5.9.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-asyncio>=0.23.0",
            "pytest-cov>=4.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "webaudit=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "Topic :: Security",
    ],
)
