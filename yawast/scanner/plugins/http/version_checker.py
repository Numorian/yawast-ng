from yawast.shared import network, output
from packaging import version
from typing import Union, Dict

_versions: Union[Dict[str, Dict[str, str]], None] = {}


def get_latest_version(
    package: str, base_version: Union[str, version.Version]
) -> Union[version.Version, None]:
    global _versions

    if _versions is not None:
        # make sure that we have data loaded
        if len(_versions) == 0:
            _get_version_data()

        if package in _versions:
            # check the type of base_version, and parse as needed
            if type(base_version) is version.Version:
                base_version = ".".join(str(base_version).split(".")[0:2])

            if base_version in _versions[package]:
                return version.parse(_versions[package][base_version])
            else:
                return version.parse(_versions[package]["latest"])
        else:
            return None
    else:
        # if it's none, that means that we've attempted to get the version data, and it failed
        output.debug(
            f"_versions is None; skipping version check for {package}:{base_version}"
        )

        return None


def _get_version_data() -> None:
    global _versions
    data: Union[Dict[str, Dict[str, Dict[str, str]]], None] = None
    data_url = "https://raw.githubusercontent.com/adamcaudill/current_versions/master/current_versions.json"

    try:
        data, _ = network.http_json(data_url)
    except Exception as error:
        output.debug(f"Failed to get version data: {error}")
        output.debug_exception()

    if data is not None and "software" in data:
        _versions = data["software"]
    else:
        _versions = None
