from setuptools import setup

packages = [
    'ciscomultiosinfocoordinate'
]

install_requires = [
    'persistentdatatools >= 2.2.7, < 3',
    'ipaddresstools >= 1.2.6, < 2',
]

tests_require = [
    'pytest',
]

setup(
    name='ciscomultiosinfocoordinate',
    version='1.3.0',
    python_requires='~=3.5',
    description='This is a library used to normalize data between Cisco OS flavors',
    keywords='ipv4 ip multicast unicast network engineer cisco nxos ios iosxr',
    url='https://github.com/btr1975/ciscomultiosinfocoordinate',
    author='Benjamin P. Trachtenberg',
    author_email='e_ben_75-python@yahoo.com',
    license='MIT',
    packages=packages,
    include_package_data=True,
    install_requires=install_requires,
    test_suite='pytest',
    tests_require=tests_require,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    ],
)