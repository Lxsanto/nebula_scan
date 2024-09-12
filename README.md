# NebulaScan

NebulaScan is an ultra-fast,  subdomain scanner developed by Luca Lorenzi at Orizon.

## Features

- Passive subdomain enumeration from multiple sources (crt.sh, VirusTotal, AlienVault, ThreatCrowd, HackerTarget)
- Brute-force subdomain discovery
- Additional information gathering for each subdomain (IP, open ports, HTTP server info, SSL details)
- Asynchronous operations for improved performance
- Colorful console output
- Results saved to a text file

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/nebulascan.git
   cd nebulascan
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the script with a target domain:

```
python nebulascan.py example.com
```

Replace `example.com` with the domain you want to scan.

## Output

The script will display results in the console and save detailed information to a file named `[domain].txt` in the current directory.

## Disclaimer

Use this tool responsibly and only on domains you have permission to scan. The authors are not responsible for any misuse or damage caused by this program.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Luca Lorenzi

## Company

Orizon
