from setuptools import setup, find_packages

setup(
    name="zasca-h-side-init",
    version="1.0.0",
    description="ZASCA H端一次性初始化脚本",
    author="ZASCA Team",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.1",
    ],
    entry_points={
        'console_scripts': [
            'h-side-init=h_side_init:main',
        ],
    },
    python_requires='>=3.6',
)