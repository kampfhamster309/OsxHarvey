from setuptools import setup, find_packages
import versioneer

with open("README.md") as readme_file:
    README = readme_file.read()

with open("HISTORY.md") as history_file:
    HISTORY = history_file.read()

setup_args = dict(
    name="osxharvey",
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description="Big White Rabbit, which can hop wifi channels while sniffing for information",
    long_description=README + "\n\n" + HISTORY,
    long_description_content_type="text/markdown",
    url="https://github.com/kampfhamster309/osxharvey",
    packages=find_packages(),
    project_urls={
        "Bug Tracker": "https://github.com/kampfhamster309/osxharvey/issues",
    },
    author="Felix Harenbrock",
    author_email="felix.harenbrock@gmx.de",
    keywords=["OSX Sniffer", "Channel Hopping", "Wifi Sniffer", "Wifi Sniffer Mac"],
    license="MIT",
    test_suite="nose.collector",
    tests_require=["nose"],
    download_url="https://pypi.org/project/osxharvey/",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
    entry_points='''
        [console_scripts]
        osxharvey=osxharvey.__main__:main
    '''
)

install_requires = [
    "ouilookup>=0.2.4",
    "protobuf>=3.15.4",
    "scapy>=2.4.5",
    "six>=1.15.0",
    "tqdm>=4.61.0",
]

if __name__ == "__main__":
    setup(**setup_args, install_requires=install_requires)
