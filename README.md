
# parse_ntds.py

`parse_ntds.py` is a Python script designed to parse an NTDS.dit file and export its content into CSV files. This tool provides a comprehensive way to extract and analyze data from NTDS files.

## Install

Before using the script, ensure you have all the necessary dependencies installed. You can install them using `pip`:

```bash
pip install -r requirements.txt
```


## Usage

To display the help message and see all available options, run:

```bash
python parse_ntds.py -h
```

### Command-line Arguments

- `-h, --help`  
  Show the help message and exit.

- `-f NTDS_FILE, --file NTDS_FILE`  
  **Required**: Path to the `ntds.dit` file.

- `-s SYSTEM_FILE, --system SYSTEM_FILE`  
  **Required**: Path to the `SYSTEM` hive file.

- `-d DOMAIN, --domain DOMAIN`  
  Domain name.

- `-o OUTPUT_DIR, --output OUTPUT_DIR`  
  Output directory. Default is the current directory.

- `-v, --verbose`  
  Increase output verbosity to DEBUG level.

- `--dump-all`  
  Dump all data except ACL (default).

- `--dump-users`  
  Dump user data.

- `--dump-groups`  
  Dump group data.

- `--dump-trusts`  
  Dump trust data.

- `--dump-domains`  
  Dump domain data.

- `--dump-ou`  
  Dump OU/container data.

- `--dump-acl`  
  Dump ACL data (**required** -d option).

## Example

To parse an NTDS.dit file and export all data to CSV files in the current directory with verbose output:

```bash
python parse_ntds.py -f /path/to/ntds.dit -s /path/to/SYSTEM -v --dump-all
```

To dump only user and group data:

```bash
python parse_ntds.py -f /path/to/ntds.dit -s /path/to/SYSTEM --dump-users --dump-groups
```

To dump all with ACL:

```bash
python parse_ntds.py -f /path/to/ntds.dit -s /path/to/SYSTEM --dump-acl -d <domain_name>
```

## About

This script was presented at the Troopers conference 2024. For more information about the conference, visit [Troopers 2024](https://troopers.de/).


---

Feel free to contribute to this project by submitting issues or pull requests. Your feedback and contributions are highly appreciated.
