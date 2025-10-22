#!/usr/bin/env python3
"""
Convert hosts file to C array for embedding in ESP32 firmware.
Usage: python embed_hosts.py esp_hosts.txt > embedded_hosts.h
"""

import sys
import os

def embed_hosts_file(input_file, output_file=None):
    """Convert hosts file to C header with embedded data."""

    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.", file=sys.stderr)
        return False

    # Read the hosts file
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            hosts_data = f.read()
    except Exception as e:
        print(f"Error reading input file: {e}", file=sys.stderr)
        return False

    # Prepare output
    if output_file:
        try:
            output = open(output_file, 'w')
        except Exception as e:
            print(f"Error opening output file: {e}", file=sys.stderr)
            return False
    else:
        output = sys.stdout

    # Generate C header
    try:
        output.write("// Auto-generated embedded hosts file\n")
        output.write("// Generated from: {}\n".format(os.path.basename(input_file)))
        output.write("#pragma once\n\n")
        output.write("#include <stddef.h>\n\n")

        # Convert to C string literal
        output.write("static const char embedded_hosts_data[] = {\n")

        # Write data as hex bytes, 16 per line
        data_bytes = hosts_data.encode('utf-8')
        for i in range(0, len(data_bytes), 16):
            chunk = data_bytes[i:i+16]
            hex_values = [f"0x{b:02x}" for b in chunk]
            output.write("    " + ", ".join(hex_values))
            if i + 16 < len(data_bytes):
                output.write(",")
            output.write("\n")

        output.write("};\n\n")
        output.write(f"static const size_t embedded_hosts_data_length = {len(data_bytes)};\n")

        # Stats
        domain_count = len([line for line in hosts_data.split('\n')
                           if line.strip() and not line.strip().startswith('#')])
        output.write(f"// Contains approximately {domain_count} domains\n")
        output.write(f"// Total size: {len(data_bytes)} bytes\n")

        if output_file:
            output.close()
            print(f"Generated {output_file} with {domain_count} domains ({len(data_bytes)} bytes)")

        return True

    except Exception as e:
        print(f"Error generating output: {e}", file=sys.stderr)
        if output_file and output:
            output.close()
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python embed_hosts.py <hosts_file> [output_file]")
        print("If output_file is not specified, output goes to stdout")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    if not embed_hosts_file(input_file, output_file):
        sys.exit(1)