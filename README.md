# Proxy Checker
Proxy Checker is a tool designed for testing multiple proxies against a specified URL, measuring the response time for each request.

## Features
- Supports multiple proxy formats
- User-Agent and Proxy timeout customization
- Multi-threaded for faster testing
- Saves results to a file

## Installation
### Clone the Repository
Clone the repository to your local machine:
```
git clone https://github.com/deanddj/ProxyChecker.git
cd ProxyChecker
```

### Install Dependencies
Install the required Python packages using pip:
```
pip install -r requirements.txt
```

## Usage
### Configure Proxies
Add your proxies in the `proxies.txt` file located in the project directory.              
Ensure each proxy is formatted correctly based on the supported formats.
```
username:password@ip:port
username:password:ip:port
ip:port:username:password
ip:port@username:password
ip:port
```
*Note: You can mix multiple formats within the same file.*

### Run the Script
Run the script and follow the prompts to test your proxies:
```
python proxy.py
```

## License
This project is licensed under the [GNU GPLv3 License](LICENSE).
