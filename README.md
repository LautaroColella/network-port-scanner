# Network Port Scanner

This is a Python-based Network Port Scanner designed for assessing active hosts and their open TCP and UDP ports. The program performs a scan on the specified network interface, checking for open ports and retrieving banners from services running on those ports. It was developed as a final project for the "Fundación Telefónica FTM Ed 19" cybersecurity course.

## Features

- **Multithreading Support**: Scans multiple ports simultaneously to speed up the scanning process.
- **TCP and UDP Scanning**: Checks for open TCP and UDP ports, retrieving service banners if available.
- **Reachability Check**: Uses ping to determine if a host is reachable before scanning.
- **JSON Output**: Saves the results of the scan in a JSON format to a specified file.
- **HTTP POST Request**: Sends the scan results to a specified server endpoint.

## Requirements

- Python 3.x
- Required libraries:
  - `socket`
  - `psutil`
  - `ipaddress`
  - `subprocess`
  - `concurrent.futures`
  - `threading`
  - `json`
  - `requests`

You can install the required libraries using pip:

```bash
pip install psutil requests
```

## Usage

To run the program, use the following command:

```bash
python network_port_scanner.py -i <interface> [-t <threads> -os <OS> -u <url> -f <filename>]
```

- `-i < interface >`: The network interface to scan (e.g. eth0, wlan0).
- `-t < threads >`: (Optional) Number of threads to use for multithreading.
- `-os < OS >`: (Optional) Name of the host operative system, can be "windows", "linux", "macos".
- `-u < url >`: (Optional) URL of the destination server to send the scan results in json format.
- `-f < filename >`: (Optional) Name of the file to write the scan results in json format.

### Example

```bash
python network_port_scanner.py -i wlan0 -t 50 -os linux -u "http://example.com/file.php" -f "scan_output.json"
```

## Output

The program prints the reachable hosts and open ports to the console during execution.

Additionally, the result of the scan will be saved in a file and sent to a URL in the following format:

```json
{
    "192.168.1.1": {
        "tcp": [
            {"port": 22, "banner": "service banner"},
            ...
        ],
        "udp": [
            {"port": 53, "banner": "service banner"},
            ...
        ]
    },
    "192.168.1.2": {
        "tcp": [],
        "udp": []
    },
    ...
}
```

## Note

- Ensure that you have the necessary permissions to scan the network.
- This tool is intended for educational purposes and should be used responsibly.

## LICENSE

MIT License

Copyright (c) 2024 Lautaro Colella

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
