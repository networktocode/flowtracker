from setuptools import find_packages, setup

setup(name='flowtracker',
      version='0.0.1',
      packages=[],
      install_requires=['netmiko', 'pycsco'],
      scripts=['flowtracker.py'],
      entry_points={
        'console_scripts': [
            'flowtracker=flowtracker:main'
            ]
        }
      )

