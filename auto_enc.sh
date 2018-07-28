#!/bin/sh
#
# udev auto exec script to run auto_enc.py
#

## Variables
dt=$(date '+%Y-%m-%d %H:%M:%S');

# passed
DEVNAME=$1
DEVPATH=$2

# set
USER="ferret" # define user to run as

## debug / test / logging

echo "DEBUG:root:$dt:auto_enc.sh: ############### START #################" >> /tmp/auto_enc_test.log

#echo "DEBUG:root:$dt:auto_enc.sh: DEVPATH: ${DEVPATH}, DEVNAME: ${DEVNAME}" >> /tmp/auto_enc_test.log
#echo "/sys${DEVPATH}" >> /tmp/auto_enc_test.log

#echo '-------------- env' >> /tmp/auto_enc_test.log
#env >> /tmp/auto_enc_test.log
#echo '-------------- file "/sys${DEVPATH}"' >> /tmp/auto_enc_test.log
#file "/sys${DEVPATH}" >> /tmp/auto_enc_test.log

# test call direct
{
export DISPLAY=:0
export XAUTHORITY=/home/$USER/.Xauthority 

# run script as user
#/bin/su -c "/home/ferret/.scripts/auto_enc.py /dev/sdb" - $USER
#/bin/su -c "/home/ferret/.scripts/auto_enc.py" - $USER

# run script (already user) - var passed on command line
/home/ferret/.scripts/auto_enc.py $DEVNAME

} & # detach / send to background

## Test if action add and DEVPATH exists as directory - udev call
#if [ "${ACTION}" = add -a -d "/sys${DEVPATH}" ]; then
#    echo "DEBUG:root:$dt:auto_enc.sh: ############### udev launch from USB Event #################" >> /tmp/auto_enc_test.log
#    #echo "add ${DEVPATH}" >> /tmp/auto_enc_test.log
#    #echo "add ${DEVNAME}" >> /tmp/auto_enc_test.log
#    
#    # group commands in script
#    {
#        # set up display for $USER
#        export DISPLAY=:0
#        export XAUTHORITY=/home/$USER/.Xauthority 
#        
#        # run script (already user)
#        /home/ferret/.scripts/auto_enc.py $DEVNAME
#        
#        # run script as user
#        #/bin/su -c "/home/ferret/.scripts/auto_enc.py ${DEVNAME}" - $USER
#        
#        
#    } & # detach / send to background
#    
#fi

echo "DEBUG:root:$dt:auto_enc.sh: ###############  END  #################" >> /tmp/auto_enc_test.log

exit 0