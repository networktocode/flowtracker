from setuptools import find_packages, setup

setup(name='flowtracker',
      version='0.0.3',
      description='Track multi-pathed flows through Cisco Nexus switches.',
      packages=[],
      install_requires=['netmiko', 'pycsco'],
      scripts=['flowtracker.py'],
      entry_points={
        'console_scripts': [
            'flowtracker=flowtracker:main'
        ]
      },
      url = 'https://github.com/networktocode/flowtracker/',
      download_url = 'https://github.com/networktocode/flowtracker/tarball/0.1',
      keywords = ['nxapi', 'nexus', 'pycsco', 'cisco']
      )

