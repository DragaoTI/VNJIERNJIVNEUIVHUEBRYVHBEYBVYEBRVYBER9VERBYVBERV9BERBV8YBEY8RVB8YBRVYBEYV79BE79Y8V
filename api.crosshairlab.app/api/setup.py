from setuptools import setup, find_packages

setup(
    name="crosshairlab-api",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn>=0.20.0",
        "pydantic>=2.5.0",
        "python-dotenv>=1.0.0",
    ],
)
