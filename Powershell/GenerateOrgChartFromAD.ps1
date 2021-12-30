####
# 
# Name: GenerateOrgChartFromAD
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This crawls through ActiveDirectory and generates
#   an org chart based on the manager field under the Organization
#   tab.
# References: 
#
####

$nomanagerstring = "0 - No Manager"
$windowname = "A.D. Organization Chart"   # Uncomment this to get all accounts
#$all = get-aduser -filter 'enabled -eq $true' -Properties name,manager,department,canonicalname,title,office,cn
# Uncomment this to get all real user accounts
$all = get-aduser -filter { ( ( enabled -eq $true ) -AND ( title -notlike 'Service Account -*' ) -AND ( title -notlike 'Mailbox -*' ) -AND ( title -notlike 'Test Account -*' ) -AND ( title -notlike 'Admin Account -*' ) ) -OR ( ( enabled -eq $true ) -AND ( title -notlike '*' ) ) } -Properties name,manager,department,CanonicalName,title,office,cn
# Uncomment this to get all real user accounts EXCEPT MEMBERS
#$all = get-aduser -filter { ( ( enabled -eq $true ) -AND ( title -notlike 'Service Account -*' ) -AND ( title -notlike 'Mailbox -*' ) -AND ( title -notlike 'Test Account -*' ) -AND ( title -notlike 'Admin Account -*' ) -AND ( title -ne 'Member' ) -AND ( title -notlike 'ORGPREFIX Member*' ) ) -OR ( ( enabled -eq $true ) -AND ( title -notlike '*' ) ) } -Properties name,manager,department,CanonicalName,title,office,cn
# Uncomment this to get all users and mailboxes
#$all = get-aduser -filter { ( ( enabled -eq $true ) -AND ( title -notlike 'Service Account -*' ) -AND ( title -notlike 'Test Account -*' ) ) -OR ( ( enabled -eq $true ) -AND ( title -notlike '*' ) ) } -Properties name,manager,department,CanonicalName,title,cn
# Uncomment this to get all mailboxes
#$all = get-aduser -filter { ( ( enabled -eq $true ) -AND ( title -like 'Mailbox -*' ) ) } -Properties name,manager,department,CanonicalName,title,office,cn
# Uncomment this to get all users and service accounts
#$all = get-aduser -filter { ( ( enabled -eq $true ) -AND ( title -notlike 'Mailbox -*' ) -AND ( title -notlike 'Test Account -*' ) ) -OR ( ( enabled -eq $true ) -AND ( title -notlike '*' ) ) } -Properties name,manager,department,CanonicalName,title,office,cn
# Uncomment this to get all service accounts
#$all = get-aduser -filter { ( ( enabled -eq $true ) -AND ( title -like 'Service Account -*' ) ) } -Properties name,manager,department,CanonicalName,title,office,cn
$arraylist = New-Object System.Collections.ArrayList
$managegroups = ($all | select-object -Property samaccountname,name,manager | Group-Object -Property manager)
function Add-Treeview {
	$treeView1.Nodes.Add($nomanagerstring,$nomanagerstring) | Out-Null
	$userslevel = New-Object System.Collections.ArrayList
	foreach ($utilisateur in $all) {
		$loop = $utilisateur.manager
		$level = 0
		While($loop -ne $null) {
			if ($loop -eq $null) {
				break
			} else {
				$level++
			}
			$loop = ($all | Where-Object {$_.distinguishedname -eq $loop}).manager
		}
		if (($level -eq 0) -and ($managegroups.name.contains($utilisateur.distinguishedname)) -ne $false) {
			$userslevel.Add([PSCUSTOMOBJECT]@{"name"=$utilisateur.name;"samaccountname"=$utilisateur.samaccountname;"Manager"="Direction";"level"=$level;"Department"=$utilisateur.department;"Office"=$utilisateur.office;"Title"=$utilisateur.title;"CanonicalName"=$utilisateur.CanonicalName}) | Out-Null
		} elseif ($level -eq 0) {
			$userslevel.Add([PSCUSTOMOBJECT]@{"name"=$utilisateur.name;"samaccountname"=$utilisateur.samaccountname;"Manager"=$nomanagerstring;"level"=$level;"Department"=$utilisateur.department;"Office"=$utilisateur.office;"Title"=$utilisateur.title;"CanonicalName"=$utilisateur.CanonicalName}) | Out-Null
		} else {
			$userslevel.Add([PSCUSTOMOBJECT]@{"name"=$utilisateur.name;"samaccountname"=$utilisateur.samaccountname;"Manager"=$utilisateur.Manager;"level"=$level;"Department"=$utilisateur.department;"Office"=$utilisateur.office;"Title"=$utilisateur.title;"CanonicalName"=$utilisateur.CanonicalName}) | Out-Null
		}
	}
	$userslevel = $userslevel | Sort-Object -Property level
	$groupedlevel = $userslevel | Group-Object -Property level
	foreach ($level in $groupedlevel) {
		foreach ($utilisateur in $level.Group) {
			$ispresent = $null
			if ($utilisateur.Manager -eq $nomanagerstring) {
				$treeView1.nodes[$nomanagerstring].nodes.add($utilisateur.samaccountname,"$($utilisateur.name) -- $($utilisateur.department) -- $($utilisateur.title) -- $($utilisateur.office) -- $($utilisateur.CanonicalName)") | Out-Null
			} else {
				$managername = $all | Where-Object {$_.distinguishedname -eq $utilisateur.Manager}
				$ispresent = $treeView1.Nodes.Find($managername.samaccountname,$true)
				if ($($ispresent.count) -eq 0 -or ($ispresent -eq $null)) {
					$treeView1.Nodes.Add($utilisateur.samaccountname,"$($utilisateur.name) -- $($utilisateur.department) -- $($utilisateur.title) -- $($utilisateur.office) -- $($utilisateur.CanonicalName)") | Out-Null
				} else {
					$ispresent[0].nodes.add($utilisateur.samaccountname,"$($utilisateur.name) -- $($utilisateur.department) -- $($utilisateur.title) -- $($utilisateur.office) -- $($utilisateur.CanonicalName)") | Out-Null
				}
			}
		}
	}
	$outofnomanagerstring = $userslevel | Where-Object {$_.level -eq 1} | Group-Object -Property manager
	foreach ($makeitup in $outofnomanagerstring) {
		$manager = $all | Where-Object {$_.distinguishedname -eq $makeitup.name}
		$node = $treeView1.Nodes.Find($manager.samaccountname,$true)
		foreach ($nod in $node) {
			$clone = $nod.clone()
			$treeView1.Nodes.Removebykey($nod.name)
			$treeview1.Nodes.Insert(0,$clone) | Out-Null
		}
	}
	$treeView1.Sorted = $true
}
[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null
[reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null
$form1 = New-Object System.Windows.Forms.Form
$treeView1 = New-Object System.Windows.Forms.TreeView
$InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Height = 950
$System_Drawing_Size.Width = 1290
$form1.ClientSize = $System_Drawing_Size
$form1.DataBindings.DefaultDataSourceUpdateMode = 0
$form1.Name = "form1"
$form1.Text = $windowname
$treeView1.DataBindings.DefaultDataSourceUpdateMode = 0
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 5
$System_Drawing_Point.Y = 5
$treeView1.Location = $System_Drawing_Point
$treeView1.Name = "treeView1"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Height = 900
$System_Drawing_Size.Width = 1280
$treeView1.Size = $System_Drawing_Size
$treeView1.TabIndex = 0
Add-Treeview
$form1.Controls.Add($treeView1)
$InitialFormWindowState = $form1.WindowState
$form1.add_Load($OnLoadForm_StateCorrection)
$form1.ShowDialog()| Out-Null
