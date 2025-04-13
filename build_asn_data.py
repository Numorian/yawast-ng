#!/usr/bin/env python3
import io
import gzip
import ipaddress
import requests
import csv


def download_and_process(url: str, output_file: str):
    # Download the compressed file
    print(f"Downloading data from {url} ...")
    response = requests.get(url)
    response.raise_for_status()  # Raise an error for a bad response

    # Use a BytesIO buffer to wrap the content bytes
    compressed_data = io.BytesIO(response.content)

    # Open the gzip file for reading
    with gzip.GzipFile(fileobj=compressed_data, mode="rb") as gz:
        # Open the output file for writing, do not write headers
        with open(output_file, "w", newline="", encoding="utf-8") as out_f:
            writer = csv.writer(out_f, delimiter="\t")
            line_count = 0
            for line in gz:
                # Decode each line from bytes to string and remove any extra whitespace
                decoded_line = line.decode("utf-8").strip()
                if not decoded_line:
                    continue

                # Expecting 5 fields: start_ip, end_ip, asn_number, country_code, description
                fields = decoded_line.split("\t")
                if len(fields) < 5:
                    print(f"Skipping malformed line: {decoded_line}")
                    continue

                start_ip_str, end_ip_str, _, country_code, description = fields

                # Convert IP addresses to integers. Handles both IPv4 and IPv6.
                try:
                    start_ip_int = int(ipaddress.ip_address(start_ip_str))
                    end_ip_int = int(ipaddress.ip_address(end_ip_str))
                except ValueError as e:
                    print(
                        f"Error converting IP to integer on line: {decoded_line}\n{e}"
                    )
                    continue

                # Combine country_code and description columns
                combined = f"{country_code} - {description}"

                # Write the processed row to the output file
                writer.writerow([start_ip_int, end_ip_int, combined])
                line_count += 1

            print(f"Processed {line_count} lines.")


def main():
    # URL of the compressed TSV file
    url = "https://api.iptoasn.com/data/ip2asn-combined.tsv.gz"
    # Name for the processed output file (without headers)
    output_file = "yawast/resources/ip2asn-combined.tsv"

    download_and_process(url, output_file)
    print(f"Data has been written to {output_file}.")


if __name__ == "__main__":
    main()
