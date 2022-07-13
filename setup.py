from setuptools import setup
from scribeAuth import __version__

setup(
    name='scribeAuth',
    python_requires='>3.10.0',
    version=__version__,
    description="Library to authenticate to Scribe's platform",
    url='https://github.com/ScribeLabsAI/scribeAuth',
    author='Ailin Venerus',
    author_email='ailin@scribelabs.ai',
    packages=['scribeAuth'],
    install_requires=['boto3'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.10',
        'Topic :: Security',
        'Typing :: Typed'
    ],
)
