#!/usr/bin/python

"""
Auto Mount Encrypted Drives on external Credentials

@Author: oliver.blakeman@carbonprojectfinance.co.uk
@Date: 2018-07-25

Shebangs: (amend #!/ path at top based on env and app)
    ferret: #!/usr/bin/python

"""

# Standard import
import sys
import os
import pwd
import time

# other
from subprocess import call, STDOUT, PIPE, Popen
FNULL = open(os.devnull, 'w') # write to /dev/null

import Tkinter as tk

# logging
import logging
logfile = "/tmp/auto_enc_test.log"
logging.basicConfig(filename=logfile,level=logging.ERROR)

################## env #################################### env #################################### env ##################

# path
current_env = os.environ['HOME']
base_dir = os.path.join(current_env, 'dev','auto_encrypted')
sys.path.append(base_dir)

# get user credentials
user_details = pwd.getpwuid(os.getuid())#[0]
user_name = user_details[0]
UID = user_details[2]
GID = user_details[3]
logging.debug('%s:%s: Script run as: %s (UID %s, GID %s)' % (time.strftime('%Y-%m-%d %H:%M:%S'), 'config', user_name, UID, GID))

# cli passed args
try:
    action = os.path.basename(sys.argv[1])
    
    try:
        device = os.path.basename(sys.argv[2])
        logging.debug('%s:%s: Search for volumes on device: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), 'config', device))

    except IndexError as e: # no second arg passed
        device = False
        logging.debug('%s:%s: Search for volumes on ALL external devices.' % (time.strftime('%Y-%m-%d %H:%M:%S'), 'config'))
    
except IndexError as e:
    logging.debug('%s:%s: No arguments passed to script' % (time.strftime('%Y-%m-%d %H:%M:%S'), 'config'))
    action = False

################## modules #################################### modules #################################### modules ##################

from crypt.secure import test_keys, secure_config, get_config

################## vars #################################### vars #################################### vars ##################

import config as config

mnt_ids = config.MNT_IDS.format(uid=UID,gid=GID) # format mount ids for user

################## functions #################################### functions #################################### functions ##################

def getpwd():
    """Password pop up dialogue."""
    func_name = sys._getframe().f_code.co_name
    logging.debug('%s:%s: Running password dialogue script.' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
    
    global password
    password = ''
    
    # main screen
    root = tk.Tk()
    root.title("Mount Encrypted")
    root.eval('tk::PlaceWindow %s center' % root.winfo_pathname(root.winfo_id()))
    
    # text
    tk.Label(root, text = 'Enter Password').pack(side = 'top', padx=60, pady=10)
    
    # password box
    pwdbox = tk.Entry(root, show = '*')
    pwdbox.pack(side = 'top', padx=60, pady=10)
    pwdbox.focus_set() # put cursor in pw box
    
    def onpwdentry(evt):
        global password
        password = pwdbox.get()
        root.destroy()
        
    def onokclick():
        global password
        password = pwdbox.get()
        root.destroy()
    
    # actions
    pwdbox.bind('<Return>', onpwdentry)
    tk.Button(root, command=onokclick, text = 'OK').pack(side = 'top', padx=60, pady=10)
    
    root.mainloop()
    return password


def confirm_mount(header,message):
    """Confirmation pop up dialogue."""
    func_name = sys._getframe().f_code.co_name
    logging.debug('%s:%s: Running confirmation dialogue script.' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
    
    # main screen
    root = tk.Tk()
    root.title(header)
    root.eval('tk::PlaceWindow %s center' % root.winfo_pathname(root.winfo_id()))
    
    # text
    tk.Label(root, text = message).pack(side = 'top', padx=60, pady=10)
    
    def onokclick():
        root.destroy()
    
    # actions
    tk.Button(root, command=onokclick, text = 'OK').pack(side = 'top', padx=60, pady=10)
    
    root.mainloop()
    return True


def auth_device(private_key):
    """Authorize public / private keypair on device."""
    func_name = sys._getframe().f_code.co_name
    logging.debug('%s:%s: Running script to find and auth device private key.' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
    
    # traverse auth device for public key
    for dir_name, subdirs_name, file_names in os.walk(config.MNT_DIR, topdown=True):
        for file_name in file_names:
            if config.PUB_KF in file_name:
                
                # get public_key
                with open(os.path.join(dir_name, file_name), "r") as pub_file:
                    public_key = pub_file.read()
                                    
                authed = test_keys(private_key,public_key)
                
                if authed :
                    return True
            
    return False


def get_mnt_devs():
    """Get list of eligible devices to mount - excluding config.MNT_EXC list."""
    func_name = sys._getframe().f_code.co_name
    logging.debug('%s:%s: Running script to find ALL available device volumes.' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
    
    mount_list =[]
    
    # find devices to mount
    for dir_name, subdirs_name, file_names in os.walk(config.DEV_DIR):
        for file_name in file_names :
            # get only eligible volumes
            if config.DEV in file_name and file_name[:3] not in config.MNT_EXC and len(file_name) == 4:
                mount_dir = os.path.join(dir_name, file_name)
                mount_list.append(mount_dir)
                
    return mount_list


def get_base_mnt_devs():
    """Get list of eligible volumes to mount for given base device."""
    func_name = sys._getframe().f_code.co_name
    logging.debug('%s:%s: Running script to find volumes for device from base device: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, device))
    
    mount_list = []
    
    # find devices to mount
    for dir_name, subdirs_name, file_names in os.walk(config.DEV_DIR):
        for file_name in file_names :
            
            # get only eligible volumes
            if device in file_name and len(file_name) > len(device):
                mount_dir = os.path.join(dir_name, file_name)
                mount_list.append(mount_dir)
                
    return mount_list


def usb_unmount():
    """Unmount device from mount dir"""
    func_name = sys._getframe().f_code.co_name
    logging.debug('%s:%s: Running script to unmount device.' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
    u_command = "sudo umount %s" % (config.MNT_DIR) # unmount command using mount dir
    success = call(u_command, stdout=FNULL, stderr=STDOUT, shell=True)
    logging.debug('%s:%s: Device %s unmounted %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, config.MNT_DIR, success))
    return success


def usb_mount(private_key):
    """Mount and verify external devices
    
    1. Mount available drives.
    2. Authorize using public / private key pair if required by config.MNT_AUTH, return true if Authed
    3. Dismount if not authed
    4. Return False if no authed devices
    
    > dev: mount device
    < True, False
    
    """
    func_name = sys._getframe().f_code.co_name
    
    ## mount and auth
    logging.debug('%s:%s: Running script to mount & auth device.' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
    if device : # get volumes from device
        mount_list = get_base_mnt_devs() 
    else: # get all device volumes
        mount_list = get_mnt_devs()
    
    ## iterate devices
    for dev in mount_list:
        logging.debug('%s:%s: Testing device volume: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, dev))
        
        # define mount commands
        u_command = "sudo umount %s" % (dev)
        m_command = "sudo mount -r -o %s --source %s --target %s" % (mnt_ids, dev, config.MNT_DIR)
        #m_command = 'sudo mount -o %s,context="system_u:object_r:samba_share_t:s0" --source %s --target %s' % (mnt_ids, dev, config.MNT_DIR)
        
        # call unmount - in case already mounted
        success = call(u_command, stdout=FNULL, stderr=STDOUT, shell=True)
        logging.debug('%s:%s: %s dismounted %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, dev, success))
        
        time.sleep(config.SYS_SLEEP)
        
        # call mount
        success = call(m_command, stdout=FNULL, stderr=STDOUT, shell=True)
        logging.debug('%s:%s: %s mounted %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, dev, success))
        
        # Auth device
        authed = auth_device(private_key)
        
        # check if authed
        if authed :
            return True
        else:
            # call unmount
            success = call(u_command, stdout=FNULL, stderr=STDOUT, shell=True)
            logging.debug('%s:%s: %s dismounted %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, dev, success))
    
    return False
            

def get_configs(private_key):
    """Get list of encrypted mount configurations."""
    func_name = sys._getframe().f_code.co_name
    logging.debug('%s:%s: Running script to decrypt encrypted mount configs.' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
    
    enc_list = []
    
    # find devices to mount
    for dir_name, subdirs_name, file_names in os.walk(config.MNT_DIR):
        for file_name in file_names :
            
            # iter required keyfiles 
            for enc_cfg in config.ENC_VOL_CFE :
                
                # match key to file
                if enc_cfg == file_name :
                    
                    # prevent duplicates
                    config.ENC_VOL_CFE.remove(enc_cfg)
                    
                    # decrypt config
                    enc_config = get_config(private_key, os.path.join(dir_name, file_name))
                    
                    if enc_config:
                        enc_list.append(enc_config)
    
    if config.ENC_VOL_CFE :
        logging.error('%s:%s: Could not retrieve all configs, remaining: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, config.ENC_VOL_CFE))
    
    return enc_list


def get_keyfiles(keyfiles):
    """Get list of keyfiles for mount."""
    func_name = sys._getframe().f_code.co_name
    logging.debug('%s:%s: Running script to identify and return keyfiles.' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
    
    kf_list = []
    
    # find devices to mount
    for dir_name, subdirs_name, file_names in os.walk(config.MNT_DIR):
        for file_name in file_names :
            
            # iter required keyfiles 
            for key in keyfiles :
                
                # match key to file
                if key == file_name :
                    
                    # prevent duplicates
                    keyfiles.remove(key)
                    
                    kf_path = os.path.join(dir_name, file_name)
                    kf_list.append(kf_path)
    
    if keyfiles :
        logging.error('%s:%s: Could not retrieve all keyfiles, remaining: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, keyfiles))
    
    return kf_list


def dismount_encrypted():
    """Dismount encrypted volumes."""
    func_name = sys._getframe().f_code.co_name
    logging.debug('%s:%s: Running encrypted volume dismount ALL script.' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
        
    denc_command = "sudo {vc} --force --dismount".format(vc=config.VC)
    proc = Popen(denc_command, stdout=PIPE, stderr=STDOUT, shell=True)
    for line in proc.stdout:
        logging.debug('%s:%s: veracrypt report: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, line))
    proc.wait()
    
    logging.debug('%s:%s: Veracrypt dismount ALL, reported: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, proc.returncode))
    
    return True


def mount_encrypted():
    """Mount encrypted volumes."""
    func_name = sys._getframe().f_code.co_name
    logging.debug('%s:%s: Running encrypted volume mount script.' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
    
    ## get private_key
    try:
        pkf = os.path.join(config.PRV_KEY_DIR.format(home=current_env), config.PRV_KF)
        with open(pkf, "r") as prv_file:
            private_key = prv_file.read()
    except IOError as e:
        logging.error('%s:%s: Private key not present: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, pkf))
        return False
    
    ## mount and ID device (pb/pk)
    mounted = usb_mount(private_key)
    if not mounted:
        logging.error('%s:%s: No device mounted.' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
        return False
    
    ## get configuration files
    enc_cfg_list = get_configs(private_key)
    if not enc_cfg_list:
        logging.error('%s:%s: No configurations present.' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
        return False
    
    # slot incrementing
    slot = 10
    
    ## iterate configured volumes
    for enc_vol in enc_cfg_list :
        
        ## Get keyfiles
        keyfiles = get_keyfiles(enc_vol.get('keyfiles',[]))
        logging.debug('%s:%s: Retrieved keyfiles' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
        
        ## password
        pw = enc_vol.get('pw',True)
        
        # password retrieval logic
        if isinstance(pw,(bool,type(None))):
            if pw:
                # get password from dialogue
                password = getpwd()
            else:
                password = None
        else:
            password = pw
        
        logging.debug('%s:%s: Retrieved password: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, '****'))
    
        ## get volume data
        try:
            volume = enc_vol['volume']
            mount_point = enc_vol['mount_point']
        except IndexError as e :
            logging.error('%s:%s: Could not retrieve volume information: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, e))
            return False
        
        # get interactive mode
        interactive = enc_vol.get('interactive',False)
        if interactive:
            interactive = ''
        else:
            interactive = '-t --non-interactive'
        
        ## check if volume is mounted on mount_point
        mount_point_taken = os.path.ismount(mount_point)  # returns boolean
        if mount_point_taken :
             ## unmount usb
            logging.debug('%s:%s: Calling unmount for device' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
            unmounted = usb_unmount()
            return False
        
        ## build veracrypt command
        
        # keyfiles and password
        if keyfiles and password:
            kf_string = ','.join(keyfiles)
            enc_command = "{vc} {ia} --keyfiles={kf} --password='{pw}' --slot={sl} {vo} {mt}".format(vc=config.VC,
                                                                                                     ia=interactive,
                                                                                                     kf=kf_string,
                                                                                                     pw=password,
                                                                                                     sl=slot,
                                                                                                     vo=volume,
                                                                                                     mt=mount_point)
        # keyfiles only
        elif keyfiles:
            kf_string = ','.join(keyfiles)
            enc_command = "{vc} {ia} --keyfiles={kf} --slot={sl} {vo} {mt}".format(vc=config.VC,
                                                                                   ia=interactive,
                                                                                                   kf=kf_string,
                                                                                                   sl=slot,
                                                                                                   vo=volume,
                                                                                                   mt=mount_point)
        # password only
        elif password:
            enc_command = """{vc} {ia} --password='{pw}' --slot={sl} {vo} {mt}""".format(vc=config.VC,
                                                                                         ia=interactive,
                                                                                         pw=password,
                                                                                         sl=slot,
                                                                                         vo=volume,
                                                                                         mt=mount_point)
        
        # no password or keyfiles ??
        else:
            enc_command = """{vc} {ia} --slot={sl} {vo} {mt}""".format(vc=config.VC,
                                                                       ia=interactive,
                                                                       sl=slot,
                                                                       vo=volume,
                                                                       mt=mount_point)
        
        ## make veracrypt call
        logging.debug('%s:%s: Calling veracrypt mount: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, enc_command))
        proc = Popen(enc_command, stdout=PIPE, stderr=STDOUT, shell=True)
        for line in proc.stdout:
            logging.debug('%s:%s: veracrypt mount output: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, line))
        proc.wait()
        
        logging.debug('%s:%s: veracrypt mount success: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, proc.returncode))
        
        # attempt dismount volume if reported error on mount, e.g. already mounted
        if proc.returncode > 0 :
            enc_command = "{vc} -t --non-interactive --dismount {vo}".format(vc=config.VC, vo=volume)
            success = call(enc_command, stdout=FNULL, stderr=STDOUT, shell=True)
            logging.debug('%s:%s: Veracrypt attempted dismount of volume %s, reported: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, volume, success))
            return False
        
        slot += 1
    
    ## unmount usb
    logging.debug('%s:%s: Calling unmount for device' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
    unmounted = usb_unmount()
    
    # report mounted volumes
    enc_list = "{vc} -t -lv".format(vc=config.VC) # verbose list
    proc = Popen(enc_list, stdout=PIPE, stderr=STDOUT, shell=True)
    for line in proc.stdout:
        logging.debug('%s:%s: veracrypt report: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, line.rstrip()))
    proc.wait()
    
    return True


################## script #################################### script #################################### script ##################

# run script if called directly
if __name__ == "__main__":
    func_name = 'auto_encrypted.__main__'
    logging.debug('%s:%s: Running script as main.' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name))
    
    if action == 'mount' : # mount encrypted files
        
        # sleep to avoid mount conflicts
        time.sleep(config.SYS_SLEEP)
        
        # perform mount
        mounted = mount_encrypted()
        logging.debug('%s:%s: Mounted encrypted volumes: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, mounted))
        
        # attempt to dismount all
        if not mounted:
            dismount_encrypted()
            usb_unmount()
        
            # dialogue
            confirmed = confirm_mount('Not Mounted','Dismounted all volumes.')
        
        exit(0)
    
    elif action == 'config' : # generate encrypted configs
        config_secured = secure_config(current_env)
        logging.debug('%s:%s: Secured config files: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, config_secured))
    
        # dialogue
        confirmed = confirm_mount('Config Encrypted','Config file successfully encrypted.')
    
    elif not action: # dismout all encrypted drives
        dismount_encrypted()
        usb_unmount()
        
        # dialogue
        confirmed = confirm_mount('Dismounted','Dismounted all volumes.')

        
        exit(0)
    
    logging.debug('%s:%s: Argument not recognised: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, action))
    exit(1)
    