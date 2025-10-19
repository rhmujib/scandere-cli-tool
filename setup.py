from setuptools import setup, find_packages

setup(
    name='scandere',
    version='1.0.0',
    author='Cybermj',
    author_email='mujibrh02@gmail.com',
    description='A simple CLI tool written in Python',
    packages=find_packages(),
    install_requires=[
        # List your dependencies here
    ],
    entry_points={
         'console_scripts': [
            'scandere = scandere.cli_tool.main:main'
        ]
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)