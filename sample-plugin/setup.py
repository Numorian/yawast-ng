from setuptools import find_packages, setup

setup(
    name="yawast-plugin-sample",
    version="0.1.0",
    description="A sample plugin for yawast-ng.",
    author="Your Name",
    author_email="your@email.com",
    packages=find_packages(),
    install_requires=[
        # Add any dependencies your plugin needs here
    ],
    entry_points={
        "yawast.plugins": [
            "yawast-plugin-sample = plugin.sample_plugin:SamplePlugin",
            "yawast-plugin-sample-hook = plugin.sample_plugin:SampleHookPlugin",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
)
