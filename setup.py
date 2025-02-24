from setuptools import setup, find_packages

setup(
    name='wifi_deauth',
    version='1.45',
    description='WiFi deauthentication tool built with Python using the Scapy library',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Flashnuke',
    author_email='flashnuke@users.noreply.github.com',
    url='https://github.com/flashnuke/wifi-deauth',
    packages=find_packages(),
    install_requires=[
        'scapy>=2.4.3'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10'
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'wifi-deauth=wifi_deauth.wifi_deauth:main',
        ],
    },
)
