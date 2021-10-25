import os.path
import re
import subprocess
import signal
import sys
import time

INTERFACE = 'tun0'
HOST = '10.10.10.244' # dynstr
# HOST = '10.10.11.108' # Return
PORTS = '--top-ports 1000'
PORT_DESC = 'top_1000'
UDP_PORTS = '--top-ports 100'
UDP_PORT_DESC = 'top_100'

MAX_NMAP_RUN_SECONDS = 10

# NOTE no finack, idle, protocol, ftp bounce scans included as they aren't useful/doable
scan_variations = {
    'syn_scan': '-sS',
    'connect_scan': '-sT',
    'ack_scan': '-sA',
    'window_scan': '-sW',
    'null_scan': '-sN',
    'fin_scan': '-sF',
    'xmas_scan': '-sX',
    "synfin_scan": '--scanflags SYNFIN',
    'sctp_init_scan': '-sY',
    'sctp_cookie_echo_scan': '-sZ',
    'udp_scan': '-sU'
}

version_scanning_varations = {
    '': '',
    '_with_version': ' -sV'
}

nmap_variations = {}

for scan_name, scan_fragment in scan_variations.items():
    for version_suffix, version_fragment in version_scanning_varations.items():
        name = f'{scan_name}{version_suffix}'
        ports = PORTS
        port_desc = PORT_DESC

        if scan_name == 'udp_scan':
            # See https://nmap.org/book/scan-methods-udp-scan.html#scan-methods-ex-udpscan-scanme3
            ports = UDP_PORTS
            port_desc = UDP_PORT_DESC

            if version_suffix == '_with_version':
                version_fragment += ' --version-intensity 0'

        # NOTE not excluding version scanning for FIN / NULL / Xmas scans

        if name =='ack_scan_with_version':
            # avoid rpc-grind clash with vmware on 0.0.0.0:902, instead of -sV:
            version_fragment = ' --script "version and not (rpc-grind.nse)"'

        fragment = f'{scan_fragment}{version_fragment} {ports}'

        
        nmap_variations[name] = (fragment, port_desc)

for name, (fragment, port_desc) in nmap_variations.items():
    output_stem = f'data/nmap_{name}_{HOST}_{port_desc}'
    incomplete_output = f'{output_stem}.lock'
    pcap_output = f'{output_stem}.pcap'

    print(f'{name} ({port_desc}):')
    if os.path.isfile(incomplete_output):
        print('Cleaning up previously incomplete run.')
        if os.path.isfile(pcap_output):
            os.remove(pcap_output)

    nmap_output = f'{output_stem}.nmap'

    if os.path.isfile(pcap_output):
        print('Previously completed run successfully.')
    else:
        with open(incomplete_output, 'w') as f:
            pass

        tcpdump_command = f'tcpdump -i {INTERFACE} -w {pcap_output}'
        nmap_command = f'nmap -n -Pn {fragment} {HOST} -oN {nmap_output} -vv'

        print('Running:',tcpdump_command)
        
        with subprocess.Popen(tcpdump_command.split(' '), stdout=sys.stdout, stderr=sys.stderr,) as tcpdump_process:
            # give tcpdump time to start packet capture
            time.sleep(0.5)

            print()
            print('Running:',nmap_command)
            with subprocess.Popen(nmap_command, stdout=sys.stdout, stderr=sys.stderr, shell=True) as nmap_process:
                nmap_process.wait(timeout=None)
            
            print()

            # give tcpdump time to complete packet capture - we know this is too short when after terminating,
            # tcpdump outputs "packets captured" number that is less than "packets received by filter"
            time.sleep(1.0)

            print('Interrupting tcpdump and waiting for clean exit...')
            tcpdump_process.send_signal(signal.SIGINT)


        os.remove(incomplete_output)

        print()

    with open(nmap_output, 'r') as f:
        content = f.read()
    
    content_without_timestamps = re.sub(r'[A-Z][a-z]{2} [A-Z][a-z]{2} [0-9]{1,2} [0-9]{1,2}:[0-9]{2}:[0-9]{2} [0-9]{4}', 'xxx xxx xx xx:xx:xx:xx xxxx', content)
    content_without_timestamps = re.sub(r'[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{1,2}:[0-9]{2}:[0-9]{2} [A-Z]{3}', 'xxxx-xx-xx xx:xx:xx xxx', content_without_timestamps)

    if content != content_without_timestamps:
        with open(nmap_output, 'w') as f:
            f.write(content_without_timestamps)
