from distutils.core import setup

setup(
    name='encryptedfile',
    version='1.1.1',
    author='thenoviceoof',
    author_email='thenoviceoof@gmail.com',
    packages=['encryptedfile'],
    url='https://github.com/thenoviceoof/encryptedfile',
    license='LICENSE.txt',
    description='Easily encrypted OpenPGP compatible files with python',
    long_description=open('README.rst').read(),
    install_requires=[
        'pycrypto >= 2.6'
    ],
)
