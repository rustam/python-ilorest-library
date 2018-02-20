from setuptools import setup, find_packages

setup(name='python-ilorest-library',
      version='2.2.0',
      description='iLO Rest Python Library',
	  author = 'Hewlett Packard Enterprise',
	  author_email = 'kocurek@hpe.com',
      classifiers=[
          'Development Status :: 3 - Alpha',
          'License :: OSI Approved :: Apache Software License',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Topic :: Communications'
      ],
      keywords='HP Enterprise',
      url='https://github.com/HewlettPackard/python-ilorest-library',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      install_requires=[
          'jsonpatch',
          'jsonpath_rw',
          'jsonpointer',
          'validictory',
          'urlparse2',
          'six'
      ])
