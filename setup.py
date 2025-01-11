from setuptools import setup, find_packages

setup(
    name="password_manager",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'cryptography>=41.0.0',
        'bcrypt>=4.0.0',
        'pyotp>=2.8.0',
        'qrcode>=7.4.0',
        'requests>=2.31.0',
        'matplotlib>=3.7.0',
        'rich>=13.7.0'
    ],
) 