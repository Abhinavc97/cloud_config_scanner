# setup.py
from setuptools import setup, find_packages

setup(
    name='cloud-config-scanner',
    version='0.1.0',
    description='Cloud configuration security scanner for AWS, Azure, GCP, and Kubernetes',
    long_description='A lightweight, developer-friendly tool that scans cloud IaC files for misconfigurations',
    author='Abhinav Chaudhary',
    author_email='abhi.199724@gmail.com',
    url='https://github.com/abhinavc97/cloud_config_scanner',
    packages=find_packages(),
    py_modules=['cli'],
    install_requires=[
        'PyYAML>=5.1',
        'click>=7.0',
        'requests>=2.25.0',
        'packaging>=20.0',
    ],
    entry_points={
        'console_scripts': [
            'ccs=cli:cli',
        ],
    },
    python_requires='>=3.7',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
)