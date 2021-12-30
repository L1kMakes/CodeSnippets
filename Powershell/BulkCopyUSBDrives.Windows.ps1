####
# 
# Name: BulkCopyUSBDrives.Windows
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This is an attempt to adapt a routine made in Linux
#   to write the contents to hundreds of USB drives at once.  It was
#   mostly unsuccessful due to limits in the number of drive letters
#   available under windows.
# References: 
#
####

$functions = {
	function DirHashCompare($sourceFileDir, $usbPath, $subDir, $driveIncomplete) {
		write-host "$Private:usbPath Entered DirHashCompare"
		$Private:workingDir = "$SourceFileDir$Local:subDir"
		$Private:workingUsbDir = "$Local:usbPath$Local:subDir"
		$Private:sourceFiles = Get-ChildItem $Private:workingDir
		ForEach ( $Local:file in $sourceFiles ) {
			if ( $Local:file -is [System.IO.DirectoryInfo] ) {
				$Private:subDirPass = "$Private:subDir\$Private:file"
				write-host "Found a directory $Private:subDirPass"
				$Private:driveIncomplete = DirHashCompare $sourceFileDir $Private:usbPath $Private:subDirPass $Private:driveIncomplete
			} else {
				$Private:sourceHash = Get-FileHash $Private:workingDir\$Private:file -Algorithm MD5
				$Private:sourceHashValue = $Private:sourceHash.Hash
				$Private:copyHash = Get-FileHash $Private:workingUsbDir\$Private:file -Algorithm MD5
				$Private:copyHashValue = $Private:copyHash.Hash
				if ( $Private:sourceHashValue -eq $Private:copyHashValue ) {
					write-host "Hash for '$Private:workingUsbDir\$Private:file' matches the source!"
				} else {
					write-host "### Hashes for '$Private:workingUsbDir\$Private:file' DO NOT MATCH!  Trying again. ###"
					$Private:driveIncomplete = $true
				}
			}
		}
		return $Private:driveIncomplete
	}
	function CopyFilesToDrive($drive, $sourceFileDir, $driveFree, $driveUsed) {
		write-host "$Private:drive.Root - Starting CopyFilesToDrive"
		$Private:drive | select-object -Property *
		$Private:fullSize = $Private:driveFree + $Private:driveUsed
		Write-Host "$Private:usedSpace $Private:freeSpace $Private:fullSize"
		if ( $Private:fullSize -eq 4018716672 ) {
			Do {
				write-host "$Private:drive.Root Writing Files to drive"
				$Private:dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
				$Private:usbPath = $Private:drive.Root
				$Private:usbPath = $Private:usbPath.Substring(0,2)
				copy-item -Recurse -Force $sourceFileDir\* $Private:usbPath
				$Private:driveIncomplete = $false
				$Private:driveIncomplete = DirHashCompare $sourceFileDir $Private:usbPath "" $Private:driveIncomplete
				
			} While ( $Private:driveIncomplete ) 
			Write-Host "File copy to $usbPath\ started at $dateStrMin is complete and validated!"
			write-host "----------"
		}
	}
}
Clear-Host
$sourceFileDir = 'C:\USB'
if ( ! ( Test-Path -Path $sourceFileDir ) ) {
	write-host "The source file directory $sourceFileDir doesn't exist, so there's nothing to do!"
} else {
	$jobs = Get-Job; foreach ($job in $jobs) { remove-job $job }
	$drives = Get-PSDrive -PSProvider 'Filesystem'
	foreach ( $drive in $drives ) {
		Start-Job -InitializationScript $functions -ScriptBlock { CopyFilesToDrive $args[0] $args[1] $args[2] $args[3] } -ArgumentList $drive, $sourceFileDir, $drive.Free, $drive.Used
		#CopyFilesToDrive $drive $sourceFileDir
	}
	Do {
		$AllJobs = Get-Job -State Running
		Sleep 10
	} While ( $AllJobs )
	$jobs = Get-Job
	foreach ($job in $jobs) { 
		Receive-Job $job
		remove-job $job 
	}
}


#$drives = Get-PSDrive -PSProvider 'Filesystem'
#foreach ( $drive in $drives ) {
#	$fullSize = $drive.Used + $drive.Free
#	if ( $fullSize -eq 4018716672 ) {
#		$usbRoot = $drive.Root
#		write-host $usbRoot
#		cd $usbRoot
#		Get-ChildItem * -Recurse | Remove-Item -Force -Recurse -Confirm:$false
#		Remove-Item -Path * -Recurse -Force -Confirm:$false
#	}
#	C:
#}
