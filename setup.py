from setuptools import setup, find_packages

setup(
    name='liveopsec',
    version='1.0.0',
    description='👻 Ghosint - Live OPSEC Monitor: A GUI-based tool for real-time operational security checks.',
    author='Your Name',
    author_email='your@email.com',
    url='https://github.com/yourusername/liveopsec',
    packages=find_packages(),
    install_requires=[],  # Add any dependencies here like 'requests'
    entry_points={
        'console_scripts': [
            'liveopsec = liveopsec.main:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Environment :: Console',
        'Environment :: X11 Applications :: GTK',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
        'Topic :: Security',
        'Topic :: Utilities',
    ],
    python_requires='>=3.6',
)
