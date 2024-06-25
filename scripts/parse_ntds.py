#!/usr/bin/env python3

from dissect.esedb import EseDB
from ntds_file import NTDSFile
from ntds_common import LocalOperations
from logging_config import logger, configure_logger
from pathlib import Path
import argparse
import os

def clean_path(path):
    """Clean and normalize the given path."""
    # Remove surrounding quotes if present
    path = path.strip('\'"')
    # Replace backslashes with forward slashes (if not on Windows)
    if os.name != 'nt':
        path = path.replace('\\', '/')
    # Return the Path object
    return str(Path(path).resolve())
# logger.disabled = True


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Python script to parse a NTDS and dumps its content to CSV files")
    parser.add_argument('-f', '--file', action='store', dest="ntds_file", required=True, help="Path to the ntds.dit file")
    parser.add_argument('-s', '--system', action='store', dest="system_file", required=True, help="Path to the SYSTEM file")
    parser.add_argument('-d', '--domain', action='store', dest="domain", help="Domain name") # TODO: automatically determine the domain name
    parser.add_argument('-o', '--output', action='store', dest="output_dir", default=f'{os.getcwd()}/output', help="Output directory. Default is the current directory")
    parser.add_argument('-v', '--verbose', action='store_true', help="Increase output verbosity to DEBUG level")
    parser.add_argument('--dump-all', action='store_true', help="Dump all data except ACL (default)", default=True)
    parser.add_argument('--dump-users', action='store_true', help="Dump user data")
    parser.add_argument('--dump-groups', action='store_true', help="Dump group data")
    parser.add_argument('--dump-trusts', action='store_true', help="Dump trust data")
    parser.add_argument('--dump-domains', action='store_true', help="Dump domain data")
    parser.add_argument('--dump-ou', action='store_true', help="Dump OU/container data")
    parser.add_argument('--dump-acl', action='store_true', help="Dump ACL data")

    args = parser.parse_args()

    # Check if --dump-acl is set and -d is missing
    if args.dump_acl and not args.domain:
        parser.error("--dump-acl requires the -d/--domain argument")

    # Determine the verbosity level
    verbosity_level = 'DEBUG' if args.verbose else 'ERROR'

    # Configure the logger
    configure_logger(verbosity_level)

    # Create output_dir if it does not exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    # Clean and normalize paths
    ntds_file = clean_path(args.ntds_file)
    system_file = clean_path(args.system_file)
    output_dir = clean_path(args.output_dir)

    dump_options = {
        'users': args.dump_users or args.dump_all,
        'groups': args.dump_groups or args.dump_all,
        'trusts': args.dump_trusts or args.dump_all,
        'domains': args.dump_domains or args.dump_all,
        'ou': args.dump_ou or args.dump_all,
        'acl': args.dump_acl,
    }

    localOperations = LocalOperations(system_file)
    bootKey = localOperations.getBootKey()
    ntds = NTDSFile(bootKey, ntds_file, output_dir)
    ntds.parse_datable()
    ntds.parse_linktable()
    ntds.update_ntdsentries()
    ntds.update_count_hashnt()
    ntds.dump_csv_domain(output_dir)
    ntds.dump_sqlite_correlations(output_dir)
    domain_SID, selected_domain = ntds.get_current_domain_SID(output_dir, args.domain, args.dump_acl) # TODO: implement a better way to retrieve the domain SID, looking in the report_domain.csv file is not optimal at all
    ntds.dump_csv_global(output_dir, selected_domain, domain_SID, dump_options)
