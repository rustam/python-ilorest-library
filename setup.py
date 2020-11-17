from setuptools import setup, find_packages

extras = {'socks': ['pysocks']}

setup(name='python-ilorest-library',
      version='3.1.1',
      description='iLO Restful Python Library',
	  author = 'Hewlett Packard Enterprise',
	  author_email = 'rajeevalochana.kallur@hpe.com',
      extras_require = extras,
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'License :: OSI Approved :: Apache Software License',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Topic :: Communications'
      ],
      keywords='Hewlett Packard Enterprise iLORest',
      url='https://github.com/HewlettPackard/python-ilorest-library',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      install_requires=[
          'jsonpatch',
          'jsonpath_rw',
          'jsonpointer',
          'urllib3',
          'six'
      ])
