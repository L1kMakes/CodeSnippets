#!/bin/bash
# 
# Script Name: BulkCopyUSBDrives.Linux.sh
# Author: Joseph Gullo (for ORGPREFIX Local 1000)
# Description: 
#    This script enumerates the USB drives connected to the computer (by block 
#    size) and, for each of them, unmounts them if auto-mounted, creates a 
#    mounting directory temporarily, mounts the drives to the temp directory, 
#    purges the contents of the drives, copies the necessary contents of the 
#    source drive from /tmp/USB to the drive, performs a differential checksum 
#    on each file copied, syncs the drive (allowing all writes to complete), 
#    then unmounts the drive and gracefully powers it off.  It then deletes the 
#    temp directories and produces some output to signal when all operations 
#    are complete.  This happens in parallel across multiple drives, which 
#    uses linux jobs for backgrounding.  As such, job detection is accomplished 
#    by the presense (or lack thereof) of lock files in /tmp.  All operations 
#    are logged to a temporary log file, but selective output is put to the 
#    screen as a progress indicator for the admin.
# 

#
# Function: prepUSB
# Description:
#    This function is called once per USB device.  The function unmounts the 
#   drive if it is mounted (via partition or disk) then blows away the 
#   partition table (as was required for a bunch of faulty drives), creates 
#   a new partition, then formats that partition with fat32.  No success 
#   checking is done as it is handled in wrapper functions.
# Parameters: 
#    1) The device code for the USB disk for this operation
#
function prepUSB {
    # Capture the date in a clean format to be used in timing and log files later
    dateStr=$(date)
    echo "$1 START PrepUSB at $dateStr"
    echo "$1 START PrepUSB at $dateStr" >> /tmp/USBWriteLog.log
    # Populate a variable to address the USB disk
    diskDev="/dev/$1"
    # Populate a variable to address the USB partition
    partDev="/dev/$1""1"
    # Create a log file
    touch "/tmp/$1.partlck"
    # If the partition is mounted, unmount it
    while [ `mount | grep "$partDev" | wc -l` -ne 0 ]
    do
        umount "$partDev"
        sleep 3
    done
    # If the disk is mounted (insted of the partition) unmount it
    while [ `mount | grep "$diskDev" | wc -l` -ne 0 ]
    do
        umount "$diskDev"
        sleep 3
    done
    # Use parted to lay down a new msdos partition table
    parted "$diskDev" --script mklabel msdos
    sleep 4
    # Use parted to make a partition with 100% of the available space
    parted "$diskDev" --script -- mkpart primary fat32 0% -1s
    sleep 4
    # Format the fat32 partition
    mkfs.vfat "$partDev"
    # Delete the lock file
    rm "/tmp/$1.partlck"
    echo "$1 END PrepUSB at $dateStr" >> /tmp/USBWriteLog.log
    echo "$1 END PrepUSB at $dateStr"
}

#
# Function: WriteUSB
# Description:
#    This function is called once per USB device.  It is the primary function 
#    which unmounts the drive, re-mounts it to a named temp directory, empties 
#    the drive, copies files to the drive, checksums the files, unmounts the 
#    drive, and powers the drive off.
# Parameters: 
#    1) The device code for the USB disk for this operation
#
function WriteUSB {
    # Capture the date in a clean format to be used in timing and log files later
    dateStr=$(date)
    # Write the date to the log file AND to the screen
    echo "$1 START at $dateStr"
    echo "$1 START at $dateStr" >> /tmp/USBWriteLog.log
    # Based on the device name, capture the device path and desired mount path to variables
    usbDevicePath="/dev/$1"
    usbMountPath="/mnt/$1"
    # Create a temporary lock file based on the USB device name
    touch "/tmp/$1.usblck"
    # Capture a variable indicating if the USB device is currently mounted
    mountedFlag=$(mount | grep -c "$usbDevicePath")
    # If the USB device is mounted, unmount it
    while [ "$mountedFlag" -ne 0 ]
    do
        # Unmount the drive, then wait 5 seconds for it to finish
        umount "$usbDevicePath"
        sleep 5
        # Re-check if the USB device is unmounted
        mountedFlag=$(mount | grep -c "$usbDevicePath")
        # If the device did NOT unmount, wait 20 seconds and try again
        if [ "$mountedFlag" -ne 0 ]
        then
            echo "### Couldn't unmount $usbDevicePath, waiting 20 seconds and trying again ###"
            echo "### Couldn't unmount $usbDevicePath, waiting 20 seconds and trying again ###" >> /tmp/USBWriteLog.log
            sleep 20
            # Attempt to unmount the USB drive again
            umount "$usbDevicePath"
            # After attempting to unmount, re-check if the device is unmounted
            mountedFlag=$(mount | grep -c "$usbDevicePath")
        fi
    done
    # Check if the desired USB mount path folder exists; if it doesn't, create it
    if [ ! -d "$usbMountPath" ]
    then
        mkdir "$usbMountPath"
    fi
    # Mount the device at the desired mount point
    mount "$usbDevicePath" "$usbMountPath"
    sleep 3
    # Initialize a flag indicating that the drive is NOT completely written to and verified
    driveIncomplete=true
    # Initialize a counter for 5 attempts to partition a drive
    partCounter=0
    # Initialize a counter for 5 attempts to write to a drive
    writeCounter=0
    # Repeat the following code until the flag indicates that the write and verification is complete
    while "$driveIncomplete"
    do
        # If the mountpoint for the USB drive doesn't exist, create the directory and cycle through the attempt again
        if [ ! -d "$usbMountPath" ]
        then
            echo "USB Path $usbMountPath Doesn't Exist!  Creating it!"
            echo "USB Path $usbMountPath Doesn't Exist!  Creating it!" >> /tmp/USBWriteLog.log
            mkdir "$usbMountPath"
        # If the drive is not mounted, attempt to mount it and cycle through the attempt again
        elif [ `mount | grep "$usbDevicePath" | wc -l` -eq 0 ]
        then
            echo "USB $usbDevicePath not mounted; mounting!"
            echo "USB $usbDevicePath not mounted; mounting!" >> /tmp/USBWriteLog.log
            mount "$usbDevicePath" "$usbMountPath"
            sleep 3  
        # If the drive is mounted but is read-only, assume corruption and go through the process of forcibly rebuilding it
        elif [ `mount | grep "$disk" | grep "(ro" | wc -l` -ne 0 ]
        then
            # Implement the limiter; only attempt to rebuild the filesystem 5 times
            if [ $partCounter -lt 5 ]
            then
                echo "USB device $usbDevicePath mountd read-only; rebuilding filesystem!  Attempt $partCounter of 5."
                echo "USB device $usbDevicePath mountd read-only; rebuilding filesystem!  Attempt $partCounter of 5." >> /tmp/USBWriteLog.log
                # We need a variable to address the USB device
                devPath=`echo $usbDevicePath | sed 's/1//g'`
                # Invoke the prepUSB function to re-prepare the filesystems and partition tables on the drive
                prepUSB "$devPath" &
                # Increment the abort counter
                partCounter=$((partCounter + 1))
                # Attempt to mount the new partition
                mount "$usbDevicePath" "$usbMountPath"
            # If we have tried 5 times, just abort alltogether.
            else
                echo "USB device $usbDevicePath is corrupted, we tried 5 times!"
                echo "USB device $usbDevicePath is corrupted, we tried 5 times!" >> /tmp/USBWriteLog.log
                exit
            fi
        # Mountpoint exists, drive is mounted, mount is r/w...proceed
        else
            # Implement the limiter; only attempt to write to the drive 5 times
            if [ $writeCounter -lt 5 ]
            then
                # Clear the USB drive in case there's anything on it
                rm -Rf "${usbMountPath:?}"/*
                # Recursively copy ALL files from the source directory to the USB drive
                cp -f -R -v "$sourceFileDir"/* "$usbMountPath" >> /tmp/USBWriteLog.log
                # Ensure all writes to the drive are complete with a sync  Immediately after, capture the exit code to a variable
                sync "/dev/$1"
                retVal="$?"
                # If the exit code is anything other than success (anything other than 0) set the flags to try again
                if [ "$retVal" -ne 0 ]
                then
                    echo "### Sync did NOT complete on $usbDevicePath, re-copying!!! ###"
                    echo "### Sync did NOT complete on $usbDevicePath, re-copying!!! ###" >> /tmp/USBWriteLog.log
                    driveIncomplete=true
                # Drive sync was successful, now check the files for differences
                else
                    # Perform a checksum differential on the drive compared against the source directory.  Immediately capture the return code to a variable
                    diff -rqs "$sourceFileDir" "$usbMountPath" >> /tmp/USBWriteLog.log
                    retVal="$?"
                    # If the exit code is anything other than success (anything other than 0) set the flags to try again
                    if [ "$retVal" -ne 0 ]
                    then
                        echo "### File hashes did NOT match on $usbDevicePath, re-copying!!! ###"
                        echo "### File hashes did NOT match on $usbDevicePath, re-copying!!! ###" >> /tmp/USBWriteLog.log
                        driveIncomplete=true
                        # Purge any files that did successfully copy
                        rm -Rf "${usbMountPath:?}"/*
                    else
                        # If the copy, sync, and differential check are all successful, set the "drive incomplete" flag to FALSE so we don't try again.
                        echo "### All processes on $usbDevicePath completed successfully!!! ###"
                        echo "### All processes on $usbDevicePath completed successfully!!! ###" >> /tmp/USBWriteLog.log
                        driveIncomplete=false
                    fi
                fi
                # Increment the counter for write attempts
                writeCounter=$((writeCounter + 1))
            # If we have tried 5 times, just abort alltogether.            
            else
                echo "USB device $usbDevicePath failed being written to, we tried 5 times!"
                echo "USB device $usbDevicePath failed being written to, we tried 5 times!" >> /tmp/USBWriteLog.log
                exit
            fi
        fi
    done
    # Populate a flag variable indicating if the USB drive is currently mounted
    mountedFlag=$(mount | grep -c "$usbDevicePath")
    # Until the device is successfully unmounted, try to unmount the drive every 20 seconds.
    while [ "$mountedFlag" -ne 0 ]
    do
        # Attempt to unmount the drive, then wait 5 seconds and check again
        umount "$usbDevicePath"
        sleep 5
        mountedFlag=$(mount | grep -c "$usbDevicePath")
        # If the unmount failed, wait 20 seconds then try again.
        if [ "$mountedFlag" -ne 0 ]
        then
            echo "### Couldn't unmount, waiting 20 seconds and trying again ###"
            echo "### Couldn't unmount, waiting 20 seconds and trying again ###" >> /tmp/USBWriteLog.log
            sleep 20
            umount "$usbDevicePath"
            # After attempting to unmount, re-check if the device is unmounted
            mountedFlag="$(mount | grep -c usbDevicePath)"
        fi
    done
    # Now that the USB drive is unmounted, delete the mount point directory
    #rmdir "$usbMountPath"
    # Capture the timestamp so we know how long the operation took
    dateStr=$(date)
    # Purge the lockfile for writing to this device
    rm "/tmp/$1.usblck"
    # Write an ending statement both to the logfile AND to the screen for admin monitoring
    echo "$1 END at $dateStr"
    echo "$1 END at $dateStr" >> /tmp/USBWriteLog.log
}

#
# Main Function
# Description: 
#    Define the source directory for files to copy to USB drives, then define 
#    the size of the destination USB keys (for detection).  Enumerate the list 
#    of attached USB drives, then kick off the partition function for each of them.  
#   Once that is all successful, kick off the write function for each of them and 
#   background that operation.  Once all writes are finished (detected by looking 
#   for the removal of all lock files placed in /tmp) the script properly powers 
#   off each USB drive for safe removal.
#

# Define the source directory for source content
sourceFileDir="/tmp/USB"
# Set the size of the USB for proper detection
usbDiskSize="4026531840"
echo "USB Disk Size is $usbDiskSize"
# Set the size of the partition for proper detection
usbPartSize="4025483264"
echo "USB Partition Size is $usbPartSize"
# Purge and Re-Create the temporary log file of this operation
rm /tmp/USBWriteLog.log
touch /tmp/USBWriteLog.log
rm /tmp/*.partlck
rm /tmp/*.usblck
# Check to see if the origin files exist, if not, abort
if [ ! -d "$sourceFileDir" ]
then
    echo "Source directory is not there, exiting!"
    echo "Source directory is not there, exiting!" >> /tmp/USBWriteLog.log
else
    # For every disk that is attached to the system with the desired size, repartition the drive
    for disk in $(lsblk -b | grep -e disk | grep -e "$usbDiskSize" | awk '{print $1}' )
    do
        # Invoke the disk partition function then background it for parallel processing
        prepUSB "$disk" &
    done
    sleep 3
    # Every 20 seconds, check to see if any USB partition lock files are present.  Loop
    while [ "$(ls -1 /tmp/ | grep -c partlck)" -ne 0 ]
    do
        echo "Waiting to finish partitioning..."
        sleep 20
    done
    # For every disk that is attached to the system with the desired size, perform the file write
    for disk in $(lsblk -b | grep -e part | grep -e "$usbPartSize" | awk '{print $1}' | sed 's|└─||g')
    do 
        # Invoke the file write function then background it for parallel processing
        WriteUSB "$disk" &
    done
    sleep 3
    # Every 20 seconds, check to see if any USB write lock files are present.  Loop
    while [ "$(ls -1 /tmp/ | grep -c usblck)" -ne 0 ]
    do
        echo "Waiting to finish writing to USB..."
        sleep 20
    done
    # For every disk that is attached to the system with the desired size, perform the power-off (safe eject) operation
    for disk in $(lsblk -b | grep -e part | grep -e "$usbPartSize" | awk '{print $1}' | sed 's|└─||g')
    do 
        echo "Powering off /dev/$disk"
        echo "Powering off /dev/$disk" >> /tmp/USBWriteLog.log
        # Power off the device in prep for safely ejecting it.
        udisksctl power-off -b "/dev/$disk"
        sleep 2
    done
    echo "ALL DONE"
    echo "ALL DONE" >> /tmp/USBWriteLog.log
    # Capture the date in a clean format to be used in log files
    dateStr=$(date)
    mv /tmp/USBWriteLog.log "/tmp/USBWriteLog.$dateStr.log"
fi

