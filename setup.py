import re
import setuptools.command.test


class PyTest(setuptools.command.test.test):

    user_options = []

    def finalize_options(self):
        setuptools.command.test.test.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest

        pytest.main(self.test_args)

version = (
    re
    .compile(r".*__version__ = '(.*?)'", re.S)
    .match(open('dsrtp/__init__.py').read())
    .group(1)
)

packages = setuptools.find_packages('.', exclude=('test',))

scripts = [
    'script/dsrtp'
]

try:
    import Cython.Build
    use_cython = True
except ImportError:
    use_cython = False
if use_cython:
    ext_modules = Cython.Build.cythonize([
        setuptools.Extension(
            'dsrtp.ext',
            ['dsrtp/ext/ext.pyx'],
            include_dirs=['dsrtp/ext/'],
            extra_compile_args=['-g', '-O0'],
            libraries=['srtp'],
        )
    ])
else:
    ext_modules = [
        setuptools.Extension(
            'dsrtp.ext',
            ['dsrtp/ext/ext.c'],
            include_dirs=['dsrtp/ext/'],
            extra_compile_args=['-g', '-O0'],
            libraries=['srtp'],
        )
    ]

extras_require = {
    'test': [
        'pytest >=2.5.2,<3',
        'pytest-cov >=1.7,<2',
        'pytest-pep8 >=1.0.6,<2',
    ],
}

setuptools.setup(
    name='dsrtp',
    version=version,
    url='https://github.com/mayfieldrobotics/dsrtp/',
    author='Mayfield Robotics',
    author_email='dev+dsrtp@mayfieldrobotics.com',
    license='MIT',
    description='Frontend for decrypting captured SRTP packets.',
    long_description=open('README.rst').read(),
    packages=packages,
    scripts=scripts,
    ext_modules=ext_modules,
    platforms='any',
    install_requires=[
        'dpkt >=1.8,<2',
    ],
    tests_require=extras_require['test'],
    extras_require=extras_require,
    cmdclass={'test': PyTest},
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
