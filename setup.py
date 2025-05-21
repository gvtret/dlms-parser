from setuptools import setup, find_packages

setup(
    name="dlms_parser",
    version="0.1.0",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'dlms-parser=dlms_parser.__main__:main'
        ],
    },
    install_requires=[
        'PyQt5>=5.15',
    ],
    python_requires='>=3.8',
)