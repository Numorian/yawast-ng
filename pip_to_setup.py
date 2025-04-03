#!/usr/bin/env python3
import os

# Try to use the built-in tomllib (Python 3.11+); otherwise, fallback to the external 'toml' package.
try:
    import tomllib  # Python 3.11+
except ImportError:
    import toml as tomllib  # pip install toml

def main():
    pipfile_path = os.path.join(os.path.dirname(__file__), "Pipfile")
    
    # Open and parse the Pipfile as TOML
    with open(pipfile_path, "rb") as f:
        pipfile_data = tomllib.load(f)

    # Get the packages section. This assumes you want production dependencies.
    packages = pipfile_data.get("packages", {})

    requirements = []
    for pkg, spec in packages.items():
        # Optionally skip keys that are not actual package requirements (like python_version)
        if pkg.lower() == "python_version":
            continue

        if isinstance(spec, str):
            # If spec is a version string (or "*" for no version constraint)
            req = pkg if spec.strip() == "*" or spec.strip() == "" else f"{pkg}{spec}"
            requirements.append(req)
        elif isinstance(spec, dict):
            # For more complex entries (e.g. VCS or extra markers), try to handle the version part.
            # This example handles a simple dict with a 'version' key.
            version = spec.get("version", "")
            # Optionally handle extras if defined (as a list of extras)
            extras = spec.get("extras")
            if extras:
                extras_str = "[" + ", ".join(extras) + "]"
                pkg_with_extras = f"{pkg}{extras_str}"
            else:
                pkg_with_extras = pkg

            req = pkg_with_extras if version.strip() == "*" or version.strip() == "" else f"{pkg_with_extras}{version}"
            requirements.append(req)
        else:
            # Fallback: just include the package name.
            requirements.append(pkg)

    # Generate the install_requires snippet as a formatted string
    output = "install_requires=[\n"
    for req in requirements:
        output += f'    "{req}",\n'
    output += "]\n"

    print(output)

if __name__ == "__main__":
    main()
