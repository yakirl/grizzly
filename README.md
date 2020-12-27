# grizzly
port scanner and port attack detector tools

Tested on python3.8.5, on linux (Should work on windows too)

### Setup

1. clone the repository:
    $git clone https://github.com/yakirl/grizzly
    $cd grizzly
2. install scapy:
    $sudo pip3 install --pre scapy[complete]
3. install requirements:
    $sudo pip3 install -r requirements.txt

### Run
Both tools should be run with admin privileges.

To run the Scanner:
    $sudo python3 port_scanner.py

* The output will be in scanner.log. log level can be changed via LOG_LVL variable
* The scanning can take time, depending on the subnets sizes and the timeout,
    as defined in the PortScanner module. To exclude specific network iterfaces, add them
    to the EXCLUDE_INTERFACES list in the module, by name. Note that UDP ports are also scanned by default, to disable it change UDP_SCAN to False.


To run the Detector:
    $sudo python3 port_detector.py

* The output will be in detector.log. log level can be changed via LOG_LVL variable

