from setuptools import setup

setup(
    name='scribeauth',
    python_requires='>=3.10.0',
    version='1.0.0',
    description="Library to authenticate to Scribe's platform",
    url='https://github.com/ScribeLabsAI/scribeAuth',
    author='Ailin Venerus',
    author_email='ailin@scribelabs.ai',
    packages=['scribeauth'],
    install_requires=['boto3', 'typing-extensions'],
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
