#!/usr/bin/env python3
"""
Script to update the download count badge in README.md.
For now, uses a stub method to return a fixed download count (in thousands).
"""
import re
from pathlib import Path

import requests


def parse_svg_count(svg: str) -> int:
    """
    Parse a count from an SVG badge (supports k, M, or exact numbers).
    """
    match = re.search(r">([\d.,]+[kM]?)<", svg)
    if match:
        val = match.group(1)
        val = val.replace(",", "")
        if val.endswith("k"):
            return int(float(val[:-1]) * 1000)
        elif val.endswith("M"):
            return int(float(val[:-1]) * 1_000_000)
        else:
            try:
                return int(val)
            except ValueError:
                pass
    return 0


def get_svg_count(url: str, parser=parse_svg_count) -> int:
    """
    Fetch a count from an SVG badge URL using the provided parser function (defaults to parse_svg_count).
    Returns the count as an integer.
    """
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        svg = resp.text
        return parser(svg)
    except Exception as e:
        print(f"Error fetching {url}: {e}")
    return 0


def get_download_count_k():
    """
    Get the total download count in thousands (k) from all sources.
    """
    total = 0
    # yawast legacy package
    legacy_py_package = get_svg_count("https://static.pepy.tech/badge/yawast")
    print(f"Legacy yawast package downloads: {legacy_py_package}")
    total += legacy_py_package

    # yawast-ng package
    ng_py_package = get_svg_count("https://static.pepy.tech/badge/yawast-ng")
    print(f"Yawast-ng package downloads: {ng_py_package}")
    total += ng_py_package

    # legacy Docker pulls

    legacy_docker_pulls = get_svg_count(
        "https://img.shields.io/docker/pulls/adamcaudill/yawast", parse_svg_count
    )
    print(f"Legacy Docker pulls: {legacy_docker_pulls}")
    total += legacy_docker_pulls

    # current Docker pulls (yawast-ng)
    ng_docker_pulls = get_svg_count(
        "https://img.shields.io/docker/pulls/adcaudill/yawast-ng",
        parse_svg_count,
    )
    print(f"Yawast-ng Docker pulls: {ng_docker_pulls}")
    total += ng_docker_pulls

    # legacy Ruby gem downloads
    legacy_ruby_downloads = get_svg_count(
        "https://img.shields.io/gem/dt/yawast", parse_svg_count
    )
    print(f"Legacy Ruby gem downloads: {legacy_ruby_downloads}")
    total += legacy_ruby_downloads

    return total // 1000


def update_readme_downloads(readme_path: str):
    readme = Path(readme_path)
    content = readme.read_text(encoding="utf-8")

    # Regex to match the downloads badge
    badge_pattern = re.compile(
        r"!\[Download Count\]\(https://img\.shields\.io/badge/downloads-[^)]*\)"
    )
    new_count = get_download_count_k()
    new_badge = f"![Download Count](https://img.shields.io/badge/downloads-{new_count}k%2B-blue)"

    # Replace the badge
    new_content, n = badge_pattern.subn(new_badge, content, count=1)
    if n == 0:
        print("No download badge found to update.")
    else:
        readme.write_text(new_content, encoding="utf-8")
        print(f"Updated download badge to {new_count}k+ downloads.")


def main():
    update_readme_downloads("README.md")


if __name__ == "__main__":
    main()
