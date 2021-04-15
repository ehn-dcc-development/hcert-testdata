#!/usr/bin/env python3

import argparse
import json
import sys

import jsonschema
import yaml


def main():
    """ Main function"""

    parser = argparse.ArgumentParser(description="Schema checker")
    parser.add_argument("schema", metavar="filename")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--input", metavar="filename")
    args = parser.parse_args()

    filename = args.schema

    with open(filename) as file:
        print("Checking schema", filename, file=sys.stderr)
        if filename.endswith(".json"):
            schema = json.load(file)
        elif filename.endswith(".yaml"):
            schema = yaml.load(file, Loader=yaml.SafeLoader)
        else:
            raise Exception("Unknown schema format")

    jsonschema.Draft4Validator.check_schema(schema)

    if args.json:
        print(json.dumps(schema, indent=4))

    if args.input:
        with open(args.input) as file:
            print("Checking input", args.input, file=sys.stderr)
            if args.input.endswith(".json"):
                data = json.load(file)
            elif args.input.endswith(".yaml"):
                data = yaml.load(file, Loader=yaml.SafeLoader)
            else:
                raise Exception("Unknown input format")
            jsonschema.validate(data, schema)


if __name__ == "__main__":
    main()
