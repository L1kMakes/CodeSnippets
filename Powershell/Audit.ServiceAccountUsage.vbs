''''
' 
' Name: Audit.ServiceAccountUsage
' Author: Joseph Gullo
' Last Modification: 2021.12.28
' Description: As part of a larger audit of service accounts,
'   this script crawls all servers and looks for actual usage
'   like services running as user, scheduled tasks running as
'   the account, etc.
' References: Various snippets of code adapted from many web 
'   searches, the sources of which are long lost
'
''''

strSearchFor = WScript.Arguments(0)
strExclude = "OU=Computers,OU=REMOTE-VM's,OU=Storage,OU=DR Appliances,OU=VMWare Appliances,OU=VMWare Hosts,OU=Xenserver Hosts,OU=TEST"

Dim rootDSE, domainObject
Set rootDSE = GetObject("LDAP://RootDSE")
domainContainer = rootDSE.Get("defaultNamingContext")
Set domainObject = GetObject("LDAP://" & domainContainer)

Set fs = CreateObject ("Scripting.FileSystemObject")

'resFilePath = ".\Results." & WScript.Arguments(0) & ".csv"
resFilePath = ".\ServiceAccountAudit.UsageResults.csv"

If Not fs.FileExists(resFilePath) Then 
	Set resFile = fs.CreateTextFile (resFilePath)
	resFile.WriteLine "Computer,Service Type,Name,State,Run As"
Else
	Set resFile = fs.OpenTextFile (resFilePath)
End If

arrSearchFor = Split(strSearchFor, ",")
arrExclude = Split(strExclude, ",")

scanComputers(domainObject)
Wscript.Echo "Scan completed, check the ServiceAccountAudit.UsageResults.csv file in this directory for the output of this script."
Wscript.Quit

Sub scanComputers(oObject)
	Dim oComputer
	For Each oComputer in oObject
		Select Case oComputer.Class
			Case "computer"
				bFound = False
				For x = 0 to UBound(arrExclude)
					If InStr(UCase(oComputer.distinguishedName), Trim(UCase(arrExclude(x)))) > 0 Then 
						bFound = True
					End If
				Next
				
				If bFound = False Then
					bPing = Ping(oComputer.cn)
					If bPing = True Then
						scanTasks(oComputer.cn)
						scanServices(oComputer.cn)
					End If
				End If
			Case "organizationalUnit" , "container"
				scanComputers(oComputer)
		End select
	Next
End Sub

Sub scanTasks(strComputer) 
	progressText strComputer,"Scanning Scheduled Tasks for" 
	Set oShell = CreateObject("WScript.Shell") 
	strPath = fs.GetParentFolderName(wscript.ScriptFullName) 
	strReturn = oShell.Run("cmd /c schtasks.exe /Query /S " & strComputer & " /v /fo csv > " & strPath & "\task.txt", 2, true) 
	Set oShell = Nothing 
	
	If Not fs.FileExists(".\task.txt") Then 
		Exit Sub 
	End If 
	
	Set getFile = fs.OpenTextFile(".\task.txt") 
	If getFile.AtEndOfStream Then 
		Exit Sub 
	End If 
	
	Do While Not getFile.AtEndOfStream strLine = getFile.ReadLine 
		If Left(strLine, 1) = chr(34) and (Not IsNull(strLine)) and (Not strLine = "") and InStr(strLine,"Task cannot be loaded") = 0 and InStr(strLine,"Scheduled Task State") = 0 Then 
			arrLine = Split(strLine, chr(34) & "," & chr(34)) 
			strAs =	arrLine(14) 
			bFound = False 
			For x = 0 to UBound(arrSearchFor) 
				If InStr(UCase(strAs), Trim(UCase(arrSearchFor(x)))) > 0 Then 
					bFound = True 
				End If 
			Next 
			If bFound = True Then 
				strName = arrLine(1) 
				strTask = arrLine(8) 
				strState =	arrLine(11) 
				resFile.WriteLine strComputer & ",Scheduled Task," & strName & "," & strState & "," & strAs 
			End If 
		End If 
	Loop 
End Sub

Sub scanServices(strComputer)
	progressText strComputer,"Scanning Services for"
	On Error Resume Next
	Err.Clear
	Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
	If Err.Number <> 0 Then
		Exit Sub
	End If
	Set colListOfServices = objWMIService.ExecQuery("Select * from Win32_Service")
	If Err.Number <> 0 Then
		Exit Sub
	End If

	For Each objService in colListOfServices
		bFound = False
		For x = 0 to UBound(arrSearchFor)
			If InStr(UCase(objService.StartName), Trim(Ucase(arrSearchFor(x)))) > 0 Then
				bFound = True
			End If
		Next
		
		If bFound = True Then
			If objService.Started = True Then
				strState = "Started"
			Else
				strState = "Not Running"
			End If
			
			strState = objService.StartMode & "/" & strState
			resFile.WriteLine strComputer & ",Service," & objService.DisplayName & "," & strState & "," & objService.StartName
		End If
   Next

   Set objWMIService = Nothing
End Sub

Function Ping(strHost)
   Dim objPing, objRetStatus
   progressText strHost, "Pinging"

   Set objPing = GetObject("winmgmts:{impersonationLevel=impersonate}").ExecQuery("select * from Win32_PingStatus where address = '" & strHost & "' AND ResolveAddressNames = TRUE")

   For Each objRetStatus in objPing
      If IsNull(objRetStatus.StatusCode) or objRetStatus.StatusCode <> 0 then 
         Ping = False
      Else
         Ping = True
      End if
   Next
End Function

Sub progressText(strComputer, strTask)
	Wscript.Echo "    " & Trim(strTask) & " " & strComputer & "..."
End Sub
