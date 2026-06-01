# Apache server-status analyzer & monitoring

A powerful, fully asynchronous command-line tool written in Python for real-time and offline analysis of Apache HTTP Server status (`/server-status`). It provides a responsive terminal layout (similar to `top` or `htop`) with automated pattern detection to quickly identify brute-force attacks, XML-RPC floods, or high-traffic domains.

## Features

- **Dual Modes:** Supports live tracking of multiple remote/local hosts as well as offline analysis of saved HTML status pages.
- **Asynchronous Architecture:** Background scraping workers fetch data concurrently without freezing the terminal interface.
- **Responsive Layout:** Utilizes terminal escape codes to provide a clean, non-scrolling UI that adapts to terminal resizing.
- **ASCII Compatible:** Uses standard cross-platform ASCII symbols for charts, graphs, and indicators, ensuring 100% compatibility across any Linux terminal or SSH client without font issues.
- **Security Insights:** Automatically scans requests for suspicious activity (e.g., WordPress login brute-forcing, XML-RPC floods, heavy AJAX usage).
- **Network & Mask Aggregation:** Aggregates incoming connections not only by individual IPs but also automatically Groups them by IPv4/IPv6 subnets (/16 and /8 equivalent masks) to pinpoint DDoS or botnet sources.

## Requirements

- `Python 3.6+`
- `beautifulsoup4`
- `requests`
- `psutil`
- `urllib3`

You can install dependencies via pip:
```
pip install requests beautifulsoup4 psutil urllib3
```

## Usage

### Live Monitoring

To monitor a local Apache instance with default settings:
```
python3 ssan.py
```

To monitor multiple live hosts concurrently with a specific refresh interval (e.g., 5 seconds):
```
python3 ssan.py --host example.com,api.example.com,stage.net --port 80 --interval 5
```

For secure connections via HTTPS:
```
python3 ssan.py --host secure-site.com --ssl --status-path /server-status
```

### Offline / Pipe Analysis

You can pass a pre-saved HTML file containing the Apache server-status page using the `-r` or `--read` flag:
```
python3 ssan.py -r /path/to/server-status.html
```

Alternatively, you can pipe the contents directly into the script:
```
curl -s http://localhost/server-status | python3 ssan.py
```

## Interactive Controls

When running in live monitoring mode, you can control the view inside the terminal using these keys:
- **[ Left Arrow ] / [ Right Arrow ]** : Switch between the analyzed hosts.
- **[ 1 - 9 ]** : Directly jump to a specific host by its index number.
- **[ Q ]** : Safely restore terminal settings and exit the analyzer.

## Credits

This project was developed with the assistance of artificial intelligence models, specifically **Google Gemini** and **DeepSeek**, which helped with code refactoring, architecture optimization, internationalization, and documentation.

## License

This project is open-source and available under the GPLv3 License.
