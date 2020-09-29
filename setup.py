from setuptools import setup

setup(
    name='python-middleware',
    version='0.1.0',
    url='https://github.com/pauvalenti/python-middleware',
    author='Pau Valentí',
    author_email='pauv@example.es',
    license='',
    packages=['python-middleware'],
    description='Flask Middleware',
    long_description='A python middleware for Flask APIs',
    keywords=['middleware', 'API'],
    classifiers=[
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet',
    ],
    install_requires=['PyJWT','Authlib','webob'],
)
