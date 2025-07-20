# INF - Internet Never Forget

A tool to visualize the DNS history of a domain, with detailed information about each IP address.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/shyybi/inf.git
cd inf
```

2. Install Python dependencies:
```bash
pip3 install -r requirements.txt
```

## Usage

To display the DNS history of a domain:
```bash
python3 inf.py {domain}
```

Example:
```bash
python3 inf.py example.com
```

To use the SecurityTrails API (optional):
- By passing the key directly:
```bash
python3 inf.py example.com --api-key {your_key}
```
- Or via a file:
```bash
python3 inf.py example.com --api-key-file path/to/key.txt
```

## Output
The script displays a colored header, then lists the historical IPs for the domain with provider, organization, country, and date information.

## Dependencies
- requests
- ipwhois
- dnspython
- colorama
