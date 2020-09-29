from setuptools import setup

setup(
    name='middleware',
    version='0.1.0',
    url='https://aasolutions.visualstudio.com/security_tools/_git/assetmanagement_api',
    author='Pau Valentí',
    author_email='pau.valenti.externo@axa-assistance.es',
    license='Apache v2.0 License',
    packages=['assetmanagement_api_client'],
    description='AssetManagement API Client',
    long_description='A python wrapper of AssetManagement API',
    keywords=['AXA', 'AssetManagement', 'ITPM', 'wrapper', 'API'],
    classifiers=[
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet',
    ],
    install_requires=['requests'],
)
