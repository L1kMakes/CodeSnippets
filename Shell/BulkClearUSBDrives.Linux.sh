####
# 
# Name: BulkClearUSBDrives.Linux
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This script identifies all USB devices of a specific
#   block size attached to a Linux system and clears the contents.
# References: 
#
####

#!/bin/bash
usbPartSize="4025483264"
echo "USB Partition Size is $usbPartSize"
#for disk in `lsblk | grep -e part | grep -e 3.8G | awk '{print $1}' | sed 's|└─||g'`
for disk in $(lsblk -b | grep -e part | grep -e $usbPartSize | awk '{print $1}' | sed 's|└─||g')
do 
    usbDevicePath="/dev/$disk"
    usbMountPath="/mnt/$disk"
    mountedFlag=$(mount | grep -c "$disk")
    while [ "$mountedFlag" -ne 0 ]
    do
        umount "$usbDevicePath"
        sleep 2
        mountedFlag=$(mount | grep -c "$disk")
        if [ "$mountedFlag" -ne 0 ]
        then
            echo "### Couldn't unmount, waiting 20 seconds and trying again ###"
            sleep 20
            umount "$usbDevicePath"
            mountedFlag=$(mount | grep -c "$disk")
        fi
    done
    if [ ! -d "$usbMountPath" ]
    then
        mkdir "$usbMountPath"
    fi
    #echo "$disk $usbDevicePath $usbMountPath"
    #lsblk | grep $disk
    mount "$usbDevicePath" "$usbMountPath"
    rm -Rf "${usbMountPath:?}"/*
    dirContents=$(ls "$usbMountPath")
    echo "USB Contents of $disk: $dirContents"
    mountedFlag=$(mount | grep -c "$usbMountPath")
    while [ "$mountedFlag" -ne 0 ]
    do
        umount "$usbMountPath"
        sleep 2
        mountedFlag=$(mount | grep -c "$usbMountPath")
        if [ "$mountedFlag" -ne 0 ]
        then
            echo "### Couldn't unmount, waiting 20 seconds and trying again ###"
            sleep 20
            umount "$usbMountPath "   
            mountedFlag=$(mount | grep -c "$usbMountPath")
        fi
    done
done

