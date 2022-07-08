from setuptools import setup

setup(
    name='scribeAuth',
    version='0.1.0',
    description='Library to Authenticate on Scribe Labs',
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
