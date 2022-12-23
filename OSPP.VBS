'Copyright (c) Microsoft Corporation. All rights reserved.
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
CONST wshOK                             =0
CONST VALUE_ICON_WARNING                =16
CONST wshYesNoDialog                    =4
CONST VALUE_ICON_QUESTIONMARK           =32
CONST VALUE_ICON_INFORMATION            =64
CONST HKEY_LOCAL_MACHINE                =&H80000002
CONST KEY_SET_VALUE                     =&H0002
CONST KEY_QUERY_VALUE                   =&H0001
CONST REG_SZ                            =1
CONST OfficeAppId                       = "0ff1ce15-a989-479d-af46-f275c6370663"
CONST STR_SYS32PATH                     = ":\Windows\System32\"
CONST STR_OSPPREARMPATH                 = "\Microsoft Office\Office16\OSPPREARM.EXE"
CONST STR_OSPPREARMPATH_DEBUG           = "\Microsoft Office Debug\Office16\OSPPREARM.EXE"
CONST REG_OSPP                          = "SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform"
CONST STR_HEARTBEATPATH                 = "\Microsoft\Office\Heartbeat\HeartbeatCache.xml"
CONST REG_SPP                           = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"
CONST REG_SCAEXP_BASE                   = "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ExperimentEcs\"
CONST REG_SCAEXP_END                    =  "\Flights\ofc5juzsw45rcw0"
CONST REG_SCAEXP_OVERRIDE               = "HKLM\SOFTWARE\Microsoft\Office\Common\Experiment\ofc5juzsw45rcw0"
CONST REG_SCAO15                        = "HKLM\SOFTWARE\Microsoft\Office\15.0\ClickToRun\Configuration\SharedComputerLicensing"
CONST REG_SCAO16                        = "HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\SharedComputerLicensing"
CONST VALUE_SCAEXP_FLAVOR               = "exp"
CONST VALUE_SCAEXP_OVERRIDE_FLAVOR      = "expoverride"
CONST VALUE_SCAO15_FLAVOR               = "o15"
CONST VALUE_SCA016_FLAVOR               = "o16"
CONST VALUE_SCAREGKEY_SINGLE_TYPE       = "single"
CONST VALUE_SCAREGKEY_PER_APP_TYPE      = "perapp"
CONST VER_INFO                          = "Version Info: 2016 1.0"
'////////////////////////////////////////////////////////////////////////////////////////
CONST MSG_NOREGRIGHTS                   = "Insufficient rights to perform operation."
CONST MSG_ISCMD_ELEVATED                = "Ensure cmd.exe is elevated (right click > run as administrator)."
CONST MSG_CREDENTIALFAILURE             = "Connection failed with passed credentials."
CONST MSG_FILENOTFOUND                  = "File not found: "                
CONST MSG_SEPERATESMALL                 = "---------------"
CONST MSG_SEPERATE                      = "---------------------------------------"
CONST MSG_PROCESSING                    = "---Processing--------------------------"
CONST MSG_EXIT                          = "---Exiting-----------------------------"
CONST MSG_UNSUPPORTED                   = "Unsupported command passed."
CONST MSG_UNSUPPORTEDOPEROS7            = "The following command is supported on Windows 7 only: "
CONST MSG_UNSUPPORTEDOPEROS8            = "The following command is supported on Windows 8 and above only: "
CONST MSG_UNSUPPORTEDLOCAL              = "The following command is supported on local machine only: "
CONST MSG_CREDENTIALERR                 = "Passing credentials is not supported for this command."
CONST MSG_SUCCESS                       = "Successfully applied setting."
CONST MSG_NOKMSLICS                     = "No Office KMS licenses were found on the system."
CONST MSG_ACTATTEMPT                    = "Installed product key detected - attempting to activate the following product:"
CONST MSG_TOKACTATTEMPT                 = "Installed product key detected - attempting to token activate the following product:"
CONST MSG_NOKEYSINSTALLED               = "<No installed product keys detected>"
CONST MSG_UNINSTALLKEYSUCCESS           = "<Product key uninstall successful>"
CONST MSG_ACTSUCCESS                    = "<Product activation successful>"
CONST MSG_OFFLINEACTSUCCESS             = "<Offline product activation successful>"
CONST MSG_KEYINSTALLSUCCESS             = "<Product key installation successful>"
CONST MSG_PARTIALKEY                    = "Last 5 characters of installed product key: "
CONST MSG_UNINSTALLKEY                  = "Uninstalling product key for: "
CONST MSG_UNRECOGFILE                   = "Unrecognized file. Office licenses have an .xrm-ms file extension."
CONST MSG_INSTALLLICENSE                = "Installing Office license: "
CONST MSG_INSTALLLICSUCCESS             = "Office license installed successfully."
CONST MSG_SEARCHEVENTSKMS               = "Searching for KMS activation events on machine: "
CONST MSG_SEARCHEVENTSRET               = "Searching for Internet activation failure events on machine: "
CONST MSG_NOEVENTSSKMS                  = "No KMS activation events found on machine: "
CONST MSG_NOEVENTSRET                   = "No failure events found on machine: "
CONST MSG_OSPPSVC_NOINSTALL             = "Error: The Software Protection Platform service is not installed."
CONST MSG_OSPPSVC_NORUN                 = "Error: The Software Protection Platform service is not running."
CONST MSG_ERRPARTIALKEY                 = "The last 5 characters of an installed product key are required to run this option. Run the /dstatus option to display the partial product key."
CONST MSG_KEYNOTFOUND                   = "<Product key not found>"
CONST MSG_CMID                          = "Client Machine ID (CMID): "
CONST MSG_CMID_NOTFOUND                 = "Not found."
CONST MSG_NOLICENSEFOUND                = "<No licenses found>"
CONST MSG_AUTHERR                       = "Authorization Error: 0x"
CONST MSG_REMILID                       = "Removed Token-based Activation License with License ID (ILID): "
CONST MSG_NOTFOUNDILID                  = "License not found with License ID (ILID): "
CONST MSG_KMSLOOKUP                     = "KMS Lookup Domain: "
CONST MSG_INFO_ONLY                     = " (for information purposes only as the status is licensed)"
CONST MSG_ACT_ERROR_FOUND_KB            = "NOTICE: A KB article has been detected for activation failure: "
CONST MSG_ACT_ERROR_KB_LINK             = "FOR MORE INFORMATION PLEASE VISIT: https://support.microsoft.com/kb/2870357#Error0x"
CONST MSG_SCAEXP                        = "SCA Mode Experiment key "
CONST MSG_SCAEXP_OVERRIDE               = "SCA Mode Experiment Override key "
CONST MSG_SCAO15                        = "SCA Mode for O15 key "
CONST MSG_SCAO16                        = "SCA Mode for O16 key "
CONST MSG_SCAREGKEY_ACTIVE              = "found ENABLED."
CONST MSG_SCAREGKEY_INACTIVE            = "found DISABLED."
'////////////////////////////////////////////////////////////////////////////////////////
CONST MSG_VLActivationType              = "Activation Type Configuration: "
'////////////////////////////////////////////////////////////////////////////////////////
CONST MSG_Act_Recent                    = "Most recent successful activation client information: "
CONST MSG_KMS_DNS                       = "KMS machine name from DNS: "
CONST MSG_KMS_DNS_ERR                   = "DNS auto-discovery: KMS name not available"
CONST MSG_ADInfoAOName                  = "Activation Object name: "
CONST MSG_ADInfoAODN                    = "AO DN: "
CONST MSG_ADInfoExtendedPid             = "AO extended PID: "
CONST MSG_ADInfoActID                   = "AO activation ID: "
CONST MSG_ACTIVATION_INTERVAL           = "Activation Interval: "
CONST MSG_RENEWAL_INTERVAL              = "Renewal Interval: "
CONST MSG_HOST_CACHING                  = "KMS host caching: "
CONST MSG_HOST_REG_OVERRIDE             = "KMS machine registry override defined: "
CONST MSG_DEFAULT_PORT                  = "1688"
'////////////////////////////////////////////////////////////////////////////////////////
CONST MSG_PID                           = "PRODUCT ID: "
CONST MSG_SKUID                         = "SKU ID: "
CONST MSG_LICENSENAME                   = "LICENSE NAME: "
CONST MSG_DESCRIPTION                   = "LICENSE DESCRIPTION: "
CONST MSG_LICSTATUS                     = "LICENSE STATUS: "
CONST MSG_LICENSED                      = " ---LICENSED--- "
CONST MSG_UNLICENSED                    = " ---UNLICENSED--- "
CONST MSG_OOBGRACE                      = " ---OOB_GRACE--- "
CONST MSG_OOTGRACE                      = " ---OOT_GRACE--- "
CONST MSG_NONGENGRACE                   = " ---NON_GENUINE_GRACE--- "
CONST MSG_NOTIFICATION                  = " ---NOTIFICATIONS--- "
CONST MSG_EXTENDEDGRACE                 = " ---EXTENDED GRACE--- "
CONST MSG_LICUNKNOWN                    = " ---UNKNOWN--- "
CONST MSG_REMAINGRACE                   = "REMAINING GRACE: "
CONST MSG_LICEXPIRY                     = "BETA EXPIRATION: "
CONST MSG_ERRCODE                       = "ERROR CODE: "
CONST MSG_ERRDESC                       = "ERROR DESCRIPTION: "
CONST MSG_ERRUNKNOWN                    = "An unknown error occurred."
CONST MSG_ERRCODEVALUE                  = "An error code must start with '0x'. Example: 0xC004F009"
'////////////////////////////////////////////////////////////////////////////////////////
CONST MSG_NOEVENTS                      = "No events found."
CONST MSG_HEARTBEAT_LOCALONLY           = "HEARTBEATCACHE.XML SUPPORTED FOR LOCAL MACHINE ONLY."
CONST MSG_SEARCHFOR                     = "SEARCHING FOR INSTANCES OF "
CONST MSG_SEARCH_FORKEY                 = "SEARCHING FOR OFFICE PRODUCT KEYS ON MACHINE: "
CONST MSG_EVENT_1013                    = "ACTIVATION SUCCESS EVENT: "
CONST MSG_EVENT_8200                    = "ACTIVATION FAILURE EVENT: "
CONST MSG_EVENT_1016                    = "INSTALL PRODUCT KEY SUCCESS EVENT: "
CONST MSG_EVENT_1017                    = "INSTALL PRODUCT KEY FAILURE EVENT: "
CONST MSG_EVENT_2011                    = "OLC-OLS EVENT: "
CONST MSG_NOKEYSINSTALLED_SUB           = "<<<<< NO INSTALLED -SUBSCRIPTION- PRODUCT KEYS DETECTED >>>>>"
CONST MSG_NOKEYSINSTALLED_PERP          = "<<<<< NO INSTALLED -PERPETUAL- PRODUCT KEYS DETECTED >>>>"
CONST MSG_KEYSINSTALLED_SUB             = "<<<<< -SUBSCRIPTION- PRODUCT KEY DETECTED. REPORTING ON ADDITIONAL PROPERTIES >>>>>"
CONST MSG_KEYSINSTALLED_PERP            = "<<<<< -PERPETUAL- PRODUCT KEY DETECTED. REPORTING ON ADDITIONAL PROPERTIES >>>>>"
CONST MSG_SCAREGKEYS                    = "SCA REGISTRY KEYS"
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
On Error Resume Next

Set WshShell = WSCript.CreateObject("WSCript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objNetwork = WSCript.CreateObject("WSCript.Network")

Dim globalResource, globalErr, foundSlUi, strSluiPath, strLocal, objWMI, objWMI1, wmiErr, productinstances, strValue, Win7, productClass, tokenClass, intIsKms, kmsCounter, isAdActivated, dlicense, foundSubKey, foundPerpKey, Win8, strSkuId, errorKBs, getHeartBeat
globalResource = ""
globalErr = ""
foundSlUi = False
Win7 = False
Win8 = False
kmsCounter = 0
isAdActivated = False
dlicense = False
strSkuId = Null

currentDir = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))

' Activation error codes for which a KB is available
errorKBs = "80070422|80070426|C004F074|80070001|80070005|8007000D|8007232B|8007251D|C004F014|C004F038|C004F039|C004F041|C004F042|C004C003|4004F040"

Select Case WSCript.Arguments.Count
    Case 0
        verifyFileExists currentDir & "ospp.htm"
        showIePopUp currentDir & "ospp.htm"
        WScript.Quit
    Case 1
        var1 = WSCript.Arguments(0)
    Case 2
        var1 = WSCript.Arguments(0)
        var2 = WSCript.Arguments(1)
    Case 3
        var1 = WSCript.Arguments(0)
        var2 = WSCript.Arguments(1)
        var3 = WSCript.Arguments(2)
    Case 4
        var1 = WSCript.Arguments(0)
        var2 = WSCript.Arguments(1)
        var3 = WSCript.Arguments(2)
        var4 = WSCript.Arguments(3)
    Case Else
End Select
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Call Main(var1,var2,var3,var4)
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Sub Main(strCommand,strMachine,strUser,strPassword)

On Error Resume Next

getEngine()
pProcessing()
getSlui()
strLocal = objNetwork.ComputerName 
strCommand = LCase(strCommand)

Select Case strCommand
    Case "/act", "/dstatus", "/dstatusall", "/dinstid", "/dtokils", _
        "/remhst", "/stokflag", "/ctokflag", "/dcmid", "/dtokcerts", "/ckms-domain", "/dpid", "/actsub", "/dstatussub"
        connectWMI strMachine,strUser,strPassword,""
        performLicAction strCommand,"",""

        If strCommand = "/dstatussub" Then
            getHeartbeatXml strMachine
            quitExit()
        End If
    Case "/dlicenseinfo"
        If strMachine <> "" Then
            WScript.Echo MSG_SEARCH_FORKEY & strMachine
        Else
            WScript.Echo MSG_SEARCH_FORKEY & strLocal 
        End If
        
        WScript.Echo MSG_SEPERATE
        
        'Connect WMI
        dlicense = True
        connectWMI strMachine,strUser,strPassword,""
        
        'Display licensestatus for all product keys
        performLicAction "/dstatusall","",""
        
        'Display PID/MachineID for sub keys
        performLicAction "/dpid","",strMachine
        
        WScript.Echo MSG_SEPERATE
        
        'Display MachineId
        getMachineId strMachine
        
        'Display HeartBeatXml
        getHeartbeatXml strMachine
        
        'Display OLC-OLS events
        getEvents MSG_EVENT_2011,"Application","2011","Microsoft Office 15",strMachine
        
        'Display SPP related events: InstallProof & SLActivate      
        If Win7 = True Then
            getEvents MSG_EVENT_1016,"Application","1016","Office Software Protection Platform Service",strMachine
            getEvents MSG_EVENT_1017,"Application","1017","Office Software Protection Platform Service",strMachine
            getEvents MSG_EVENT_1013,"Application","1013","Office Software Protection Platform Service",strMachine
            getEvents MSG_EVENT_8200,"Application","8200","Office Software Protection Platform Service",strMachine
        Else
            getEvents MSG_EVENT_1016,"Application","1016","Microsoft-Windows-Security-SPP",strMachine
            getEvents MSG_EVENT_1017,"Application","1017","Microsoft-Windows-Security-SPP",strMachine
            getEvents MSG_EVENT_1013,"Application","1013","Microsoft-Windows-Security-SPP",strMachine
            getEvents MSG_EVENT_8200,"Application","1014","Microsoft-Windows-Security-SPP",strMachine
        End If

        WScript.Echo MSG_SEPERATE

        'Display SCA mode status
        checkScaStatus

        quitExit()
    Case "/dhistoryacterr", "/dhistorykms"
        connectWMI strMachine,strUser,strPassword,""
        performLicAction strCommand,"",strMachine
    Case "/puserops", "/duserops"
        connectWMI strMachine,strUser,strPassword,"reg"
        performRegAction strCommand
    Case "/osppsvcrestart", "/osppsvcauto"
        connectWMI strMachine,strUser,strPassword,""
        performServiceAction strCommand
    Case "/help", "help", "?", "/?", "/?"
        verifyFileExists currentDir & "ospp.htm"
        showIePopUp currentDir & "ospp.htm"
        quitExit()
    Case "/regmof"
        registerMof "osppwmi.mof"
    Case "/rearm"
        If strMachine = "" Then
            reARM ""
        Else
            globalPopFailure MSG_UNSUPPORTEDLOCAL & vbCr & strCommand,True
        End If
        quitExit()
    Case "/version"
        globalPopSuccess VER_INFO,True
    Case Else
        pos = InStr(strCommand,":")
        
        Select Case pos
            Case 6
                getCommand = Left(strCommand,5)
            Case 7
                getCommand = Left(strCommand,6)
            Case 8
                getCommand = Left(strCommand,7)
            Case 9
                getCommand = Left(strCommand,8)
            Case 13
                getCommand = Left(strCommand,12)
            Case Else
                globalPopFailure MSG_UNSUPPORTED,True
        End Select
        
        Select Case getCommand
            Case "/skms-domain", "/actype", "/inpkey", "/unpkey", "/inslic", "/actcid", "/sethst", "/setprt", "/ddescr", "/rtokil", "/tokact", "/cachst", "/rearm", "/pstatus", "/actp"
                strValue = Replace(strCommand,getCommand & ":","")
                If strValue = "" Then
                    globalPopFailure MSG_UNSUPPORTED & " A value is required for: " & strCommand,True
                End If
                
                If getCommand = "/ddescr" Then
                    If Left(strValue,2) = "0x" Then
                        getDescription strValue,""
                    Else
                        WScript.Echo MSG_ERRCODEVALUE
                        quitExit()
                    End If
                ElseIf getCommand = "/rearm" Then
                    If strMachine = "" Then
                        reARM strValue
                Else
                    globalPopFailure MSG_UNSUPPORTEDLOCAL & vbCr & strCommand,True
                End If
                quitExit()
                Else
                    connectWMI strMachine,strUser,strPassword,""
                    performLicAction getCommand,strValue,""
                    If getCommand = "/pstatus" And getHeartBeat = True Then
                        getHeartbeatXml strMachine
                    End If
                    quitExit()
                End If
            Case Else
                globalPopFailure MSG_UNSUPPORTED,True
        End Select
End Select

End Sub
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function showIePopUp(strPath)

On Error Resume Next

Set objExplorer = CreateObject("InternetExplorer.Application")
    With objExplorer
            .Navigate strPath
            .ToolBar = 0
            .StatusBar = 0
            .Width = 1000
            .Height = 593 
            .Left = 1
            .Top = 1
            .Visible = 1
    End With
        
End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function getEngine()

strEngine = LCase(Right(WScript.FullName,12))
If strEngine <> "\cscript.exe" Then
    WshShell.Popup "Unable to perform operation. " & WSCript.ScriptName & " requires the cscript engine." & _
     vbCr & "Command line example: cscript ospp.vbs ?", _
    ,WSCript.ScriptName, VALUE_ICON_WARNING
    WScript.Quit
End If

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function WMIDateStringToDate(dtmEventDate)

WMIDateStringToDate = CDate(Mid(dtmEventDate, 5, 2) & "/" & _
Mid(dtmEventDate, 7, 2) & "/" & Left(dtmEventDate, 4) _
& " " & Mid (dtmEventDate, 9, 2) & ":" & _
Mid(dtmEventDate, 11, 2) & ":" & Mid(dtmEventDate, _
13, 2))

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function getDescription(strSearch,cType)

If foundSlUi <> True Then
    If cType <> "wmi" Then
        globalPopFailure "slui.exe not found.",True
        quitExit()
    End If
Else
    Set objScriptExec = WshShell.Exec (strSluiPath & " 0x2a " & strSearch)
    readOut = objScriptExec.StdOut.ReadAll
    quitExit()
End If

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function checkRegRights(wmiObject,strKeyPath)

On Error Resume next

wmiObject.CheckAccess HKEY_LOCAL_MACHINE, strKeyPath, KEY_SET_VALUE, _
    bHasAccessRight

If bHasAccessRight = True Then
    'Success
Else
    globalPopFailure MSG_NOREGRIGHTS & vbCr & MSG_ISCMD_ELEVATED,True
End If   

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function quitExit()

Set WshShell = Nothing
Set objFSO = Nothing
Set objNetwork = Nothing
Set objWMI = Nothing

WScript.Echo MSG_SEPERATE
WScript.Echo MSG_EXIT
WSCript.Quit

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function verifyFileExists(file)

If Not objFSO.FileExists(file) Then
    If file = currentDir & "slerror.xml" Then
        WScript.Echo "[" & MSG_FILENOTFOUND & file &  "  Unable to display error description.]"
    ElseIf file = currentDir & "ospp.htm" Then
        globalPopFailure MSG_FILENOTFOUND & vbCr & file,False
        quitExit()
    Else
        globalPopFailure MSG_FILENOTFOUND & vbCr & file,True
    End If
End If

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function registerMof(strFile)

For Each Drv In objFSO.Drives
    If Drv.DriveType=2 Then
        If objFSO.FileExists(Drv.DriveLetter & STR_SYS32PATH & "wbem\mofcomp.exe") Then
            foundComp = True
            strMofExePath = Drv.DriveLetter & STR_SYS32PATH & "wbem\mofcomp.exe"
            If objFSO.FileExists(Drv.DriveLetter & STR_SYS32PATH & "wbem\" & strFile) Then
                foundMof = True
                strOWmi = Drv.DriveLetter & STR_SYS32PATH & "wbem\" & strFile
                Set objScriptExec = WshShell.Exec (strMofExePath & " " & strOWmi)
                readOut = objScriptExec.StdOut.ReadAll
                WScript.Echo readOut
                quitExit()
            End If
        End If
    End If
Next

If foundComp <> True Then
    globalPopFailure MSG_FILENOTFOUND & Replace(STR_SYS32PATH,":","") & "wbem\mofcomp.exe",True
Else
    If foundMof <> True Then
        globalPopFailure MSG_FILENOTFOUND & Replace(STR_SYS32PATH,":","") & "wbem\osppwmi.mof",True
    End If
End If

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function pProcessing()

WScript.Echo MSG_PROCESSING
WScript.Echo MSG_SEPERATE
    
End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function getSlui()

For Each Drv In objFSO.Drives
    If Drv.DriveType=2 Then
        If objFSO.FileExists(Drv.DriveLetter & STR_SYS32PATH & "slui.exe") Then
            strSluiPath = Drv.DriveLetter & STR_SYS32PATH & "slui.exe"
            foundSlUi = True
            Exit For
        End If
    End If
Next

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
' Returns the encoding for a givven file.
' Possible return values: ascii, unicode, unicodeFFFE (big-endian), utf-8
Function GetFileEncoding(strFileName)
    Dim strData
    Dim strEncoding

    Set oStream = CreateObject("ADODB.Stream")

    oStream.Type = 1 'adTypeBinary
    oStream.Open
    oStream.LoadFromFile(strFileName)

    ' Default encoding is ascii
    strEncoding =  "ascii"

    strData = BinaryToString(oStream.Read(2))

    ' Check for little endian (x86) unicode preamble
    If (Len(strData) = 2) and strData = (Chr(255) + Chr(254)) Then
        strEncoding = "unicode"
    Else
        oStream.Position = 0
        strData = BinaryToString(oStream.Read(3))

        ' Check for utf-8 preamble
        If (Len(strData) >= 3) and strData = (Chr(239) + Chr(187) + Chr(191)) Then
            strEncoding = "utf-8"
        End If
    End If

    oStream.Close

    GetFileEncoding = strEncoding
    
End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
' Converts binary data (VT_UI1 | VT_ARRAY) to a string (BSTR)
Function BinaryToString(dataBinary)  
    Dim i
    Dim str

    For i = 1 To LenB(dataBinary)
        str = str & Chr(AscB(MidB(dataBinary, i, 1)))
    Next

    BinaryToString = str
    
End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
' Returns string containing the whole text file data. 
' Supports ascii, unicode (little-endian) and utf-8 encoding.
Function ReadAllTextFile(strFileName)
    Dim strData
    Set oStream = CreateObject("ADODB.Stream")

    oStream.Type = 2 'adTypeText
    oStream.Open
    oStream.Charset = GetFileEncoding(strFileName)
    oStream.LoadFromFile(strFileName)

    strData = oStream.ReadText(-1) 'adReadAll

    oStream.Close

    ReadAllTextFile = strData
    
End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function sppErrHandle(strCommand)

globalErr = Hex(Err.Number)

Select Case Err.Number
    Case 0
        'Success
        Select Case strCommand
            Case "/act","/tokact","/actsub","/actp"
                WScript.Echo MSG_ACTSUCCESS
            Case "/inpkey"
                WScript.Echo MSG_KEYINSTALLSUCCESS
                quitExit()
            Case "/inslic"
                WScript.Echo MSG_INSTALLLICSUCCESS
                quitExit()
            Case "/ckms-domain","/skms-domain","/actype","/sethst","/setprt","/remhst","/stokflag","/ctokflag","/cachst"
                WScript.Echo MSG_SUCCESS
                quitExit()
            Case "/rtokil"
                WScript.Echo MSG_REMILID & UCase(strValue)
                quitExit()
            Case "/unpkey"
                WScript.Echo MSG_UNINSTALLKEYSUCCESS
                quitExit()
            Case Else
        End Select
    Case Else
        verifyFileExists currentDir & "slerror.xml"
        getResource("err" & "0x" & globalErr)
        If globalResource = "" Then
            If Len(globalErr) <> "8" Then
                WScript.Echo MSG_ERRDESC & MSG_ERRUNKNOWN & " (0x" & globalErr & ")"
            Else
                If foundSlUi = True Then
                    WScript.Echo MSG_ERRCODE & "0x" & globalErr
                    WScript.Echo MSG_ERRDESC & "Run the following: cscript ospp.vbs /ddescr:0x" & globalErr
                Else
                    WScript.Echo MSG_ERRCODE & "0x" & globalErr 
                End If
            End If
            If strCommand <> "/act" And strCommand <> "/actsub" And strCommand <> "/actp" Then
                quitExit()
            End If
        Else
            WScript.Echo MSG_ERRCODE & "0x" & globalErr 
            Wscript.Echo MSG_ERRDESC & globalResource
        End If
        
        If strCommand = "/dtokcerts" Or strCommand = "/ignore" Then
            quitExit()
        End If
End Select

If globalErr = "C004F074" Then
    WScript.Echo "To view the activation event history run: cscript " & WScript.ScriptName & " /dhistorykms"
End If

If strCommand = "/act" And globalErr <> "0" Then
    ' If a KB article is found, show the KB link
    lookupKBArticle(globalErr)
End If

globalResource = ""
globalErr = ""
Err.Clear

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function wmiErrHandle()

Select Case Err.Number
    Case 0
        'Successs
    Case 424
        globalPopFailure MSG_ERRCODE & Err.Number & vbCr & MSG_ERRDESC & MSG_CREDENTIALFAILURE,True            
    Case Else
        If Err.Description <> "" Then
            globalPopFailure MSG_ERRCODE & Err.Number & vbCr & MSG_ERRDESC & Err.Description,True
        Else
            globalPopFailure "An error occurred while making the connection." & vbCr & MSG_ERRCODE & Err.Number,True
        End If
End Select

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function setRegValue(wmiObject,opsValue,strValueName)

On Error Resume Next

Err.Clear()
If Win7 = True Then
    strKeyPath = REG_OSPP
Else
    strKeyPath = REG_SPP
End If

Select Case strValueName
    Case "UserOperations"
        wmiObject.CreateKey HKEY_LOCAL_MACHINE,strKeyPath
        wmiObject.SetDWORDValue HKEY_LOCAL_MACHINE,_
            strKeyPath,strValueName,opsValue
    Case Else
End Select

wmiErrHandle()
WScript.Echo MSG_SUCCESS
quitExit()

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function getResource(resource)

On Error Resume Next
Set xmlDoc = CreateObject("Msxml2.DOMDocument.6.0") 
xmlDoc.load(currentDir & "slerror.xml") 
Set ElemList = xmlDoc.getElementsByTagName(resource) 
resValue = ElemList.item(0).text
globalResource = resValue 

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function globalPopSuccess(strSuccess,boolQuit)

If boolQuit = True Then
    WshShell.Popup strSuccess,,WScript.ScriptName, wshOK + VALUE_ICON_INFORMATION
    quitExit()
Else
    WshShell.Popup strSuccess,,WScript.ScriptName, wshOK + VALUE_ICON_INFORMATION
End If

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function globalPopFailure(strFailure,boolQuit)

If boolQuit = True Then
    WshShell.Popup strFailure,,WScript.ScriptName, wshOK + VALUE_ICON_WARNING
    quitExit()
Else
    WshShell.Popup strFailure,,WScript.ScriptName, wshOK + VALUE_ICON_WARNING
End If

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function connectWMI(strMachine,strUser,strPassword,ctype)

On Error Resume Next

If ctype = "" Then
    If strMachine = "" Or LCase(strMachine) = LCase(strLocal) Then
        Set objWMI = GetObject("winmgmts:" _
                & "{impersonationLevel=impersonate}!\\" & "." & "\root\cimv2")
    Else
        If strUser = "" And strPassword = "" Then
            Set objWMI = GetObject("winmgmts:" _
                & "{impersonationLevel=impersonate}!\\" & strMachine & "\root\cimv2")
        Else
            Set objSWbemLocator = CreateObject("WbemScripting.SWbemLocator")
            Set objWMI = objSWbemLocator.ConnectServer _
                (strMachine, "\root\cimv2", strUser, strPassword)
            wmiErr = CStr(Hex(Err.Number))
            If Len(wmiErr) = "8" Then
                getDescription "0x" & wmiErr,"wmi"
            End If
            objWMI.Security_.ImpersonationLevel = 3
        End If
    End If
Else
    If strUser <> "" Then
        globalPopFailure MSG_CREDENTIALERR,True
    End If

    If strMachine = "" Or LCase(strMachine) = LCase(strLocal) Then
        Set objWMI1 = GetObject("winmgmts:" _
            & "{impersonationLevel=impersonate}!\\" & "." & "\root\default:StdRegProv")
            
        Set objWMI = GetObject("winmgmts:" _
                & "{impersonationLevel=impersonate}!\\" & "." & "\root\cimv2")
    Else
        Set objWMI1 = GetObject("winmgmts:" _
            & "{impersonationLevel=impersonate}!\\" & strMachine & "\root\default:StdRegProv")
            
        Set objWMI = GetObject("winmgmts:" _
                & "{impersonationLevel=impersonate}!\\" & strMachine & "\root\cimv2")
    End If
End If

wmiErrHandle()
setWinOS()

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Private Function TkaGetSigner()

On Error Resume Next

    If Win7 = True Then 
        Set TkaGetSigner = WScript.CreateObject("OSPPWMI.OSppWmiTokenActivationSigner")
    Else
        Set TkaGetSigner = WScript.CreateObject("SPPWMI.SppWmiTokenActivationSigner")
    End If
    
    If Hex(Err.Number) = "80020009" Then
        globalPopFailure MSG_ERRCODE & "0x" & Hex(Err.Number) & vbCr & MSG_ERRDESC & Err.Description,True
    End If

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function TkaPrintCertificate(strThumbprint)

    arrParams = Split(strThumbprint, "|")
    WScript.Echo "Thumbprint: " & arrParams(0)
    WScript.Echo "Subject: " & arrParams(1)
    WScript.Echo "Issuer: " & arrParams(2)
    vf = FormatDateTime(CDate(arrParams(3)), vbShortDate)
    WScript.Echo "Valid From: " & vf
    vt = FormatDateTime(CDate(arrParams(4)), vbShortDate)
    WScript.Echo "Valid To: " & vt
    WScript.Echo MSG_SEPERATE
    
End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function ExecuteQuery(strSelect,strWhere,strClass)
    
Err.Clear
    
If strWhere = "" Then
    Set productinstances = objWMI.ExecQuery("SELECT " & strSelect & " FROM " & strClass)
Else
    Set productinstances = objWMI.ExecQuery("SELECT " & strSelect & " FROM " & strClass & " WHERE " & strWhere)
End If
    
sppErrHandle ""

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function performLicAction(strCommand,strValue,strMachine)

On Error Resume Next

If strCommand = "/dhistorykms" Or strCommand = "/dhistoryacterr" Then
    verifyFileExists currentDir & "slerror.xml"
    If strCommand = "/dhistorykms" Then
        '12288 = KMS Activation event id
        eventCode = "12288"
        strSrcEvents = MSG_SEARCHEVENTSKMS
        strNoEvents = MSG_NOEVENTSSKMS
    Else
        '8200 = Internet Activation event id
        eventCode = "8200"
        strSrcEvents = MSG_SEARCHEVENTSRET
        strNoEvents = MSG_NOEVENTSRET
    End If
    
    If strMachine <> "" Then
        WScript.Echo strSrcEvents & strMachine
    Else
        WScript.Echo strSrcEvents & strLocal
    End If
    
    WScript.Echo "Event ID: " & eventCode
    WScript.Echo vbCr
    Set objEvents = objWMI.ExecQuery _
        ("Select * from Win32_NTLogEvent Where Logfile = 'Application' and " _
        & "EventCode = '" & eventCode & "'")
        If objEvents.Count > 0 Then
            For each objEvent in objEvents
                If strCommand = "/dhistoryacterr" Then
                    i = i + 1
                    dtmEventDate = objEvent.TimeWritten
                    strTimeWritten = WMIDateStringToDate(dtmEventDate)
                    WScript.Echo "Coordinated Universal Time Written: " & strTimeWritten
                    strReplCrs = Replace(objEvent.Message,vbCrLf,"")
                    WScript.Echo "MESSAGE: " & strReplCrs
                    strhr10 = Right(strReplCrs,10)
                    getResource("err" & strhr10)
                    If globalResource = "" Then
                        If foundSlUi = True Then
                            WScript.Echo MSG_ERRDESC & "Run the following: cscript ospp.vbs /ddescr:" & strhr10
                        Else
                            WScript.Echo MSG_ERRDESC & "Not available."
                        End If
                    Else
                        Wscript.Echo MSG_ERRDESC & globalResource
                    End If
                    WScript.Echo MSG_SEPERATE        
                Else
                    strhr10 = Mid(objEvent.Message,90,10)
                    strReplCrs = Replace(objEvent.Message,vbCrLf,"")
                    If Right(strReplCrs,2) = " 5" Then
                        strReplStrs = Replace(strReplCrs,"The client has sent an activation request to the key management service machine.Info:","")
                        dtmEventDate = objEvent.TimeWritten
                        strTimeWritten = WMIDateStringToDate(dtmEventDate)
                        WScript.Echo "Coordinated Universal Time Written: " & strTimeWritten
                        intColon = InStr(strReplStrs,":")
                        strErrHost = Left(strReplStrs,intColon)
                        strErrHost = Trim(strErrHost)
                        strErrHost = Replace(strErrHost,":","")
                        WScript.Echo "ERROR/HOST: " & strErrHost
                        Select Case strhr10
                            Case "0x00000000"
                                WScript.Echo MSG_ERRDESC & "N/A"
                            Case Else
                                getResource("err" & strhr10)
                                If globalResource = "" Then
                                    If foundSlUi = True Then
                                        WScript.Echo MSG_ERRDESC & "Run the following: cscript ospp.vbs /ddescr:" & strhr10
                                        ' If a KB article is found, show the KB link
                                        lookupKBArticle(Right(strhr10, 8))
                                    Else
                                        WScript.Echo MSG_ERRDESC & "Not available."
                                    End If
                                Else
                                    Wscript.Echo MSG_ERRDESC & globalResource
                                    ' If a KB article is found, show the KB link
                                    lookupKBArticle(Right(strhr10, 8))
                                End If
                        End Select
                        WScript.Echo MSG_SEPERATE
                    End If
                End If
            Next
        Else
            WScript.Echo MSG_SEPERATE
            If strMachine <> "" Then
                WScript.Echo strNoEvents & strMachine
            Else
                WScript.Echo strNoEvents & strLocal
            End If
            WScript.Echo MSG_SEPERATE
        End If
        quitExit()
End If

'Verify osppsvc service is installed for win7 case
If Win7 = True Then
    Set colListOfServices = objWMI.ExecQuery _
        ("Select * from Win32_Service ")
    For Each objService in colListOfServices
        If objService.Name = "osppsvc" Then
            installed = True
            Exit For
        End If
    Next
        
    If installed <> True Then
        globalPopFailure MSG_OSPPSVC_NOINSTALL,True
    End If
End If
        
Select Case strCommand
    'The following operations are performed @ a service level
    Case "/inpkey", "/dcmid", "/inslic", "/cachst", "/stokflag", "/ctokflag", "/dstatus", "/dstatusall", "/dpid", "/dstatussub", "/pstatus"
        If Win7 = True Then
            For Each objService in objWMI.InstancesOf("OfficeSoftwareProtectionService")
                Set objOspp = objService
                Exit For
            Next
        Else
            'Win8 and beyond
            For Each objService in objWMI.InstancesOf("SoftwareLicensingService")
                Set objOspp = objService
                Exit For
            Next
        End If
    Case Else
End Select

sppErrHandle ""

If strCommand = "/inpkey" Then
    i = i + 1
    Err.Clear
    objOspp.InstallProductKey(strValue)
    sppErrHandle(strCommand)
ElseIf strCommand = "/cachst" Then
    i = i + 1
    If strValue = "true" Then
        objOspp.DisableKeyManagementServiceHostCaching(False)
        sppErrHandle(strCommand)
    ElseIf strValue = "false" Then
        objOspp.DisableKeyManagementServiceHostCaching(True)
        sppErrHandle(strCommand) 
    Else
        globalPopFailure MSG_UNSUPPORTED & " A TRUE or FALSE value is required for: " & strCommand,True
    End If
ElseIf strCommand = "/dcmid" Then
    If Win8 = True Then
        'Check if KMS key installed. If yes retrieve the SKUID value.
        ExecuteQuery "ID, ApplicationId, Description, Name","ApplicationId = '" & OfficeAppId & "' " & "AND PartialProductKey <> NULL ",productClass
        For each instance in productinstances
            sppErrHandle ""
            intIsKms = InStr(UCase(instance.Description),"KMS")
            If intIsKms <> 0 Then
                strSkuId = instance.ID
                Exit For
            End If
        Next
        
        If strSkuId = Null Then 
            WScript.Echo MSG_CMID & MSG_CMID_NOTFOUND
            quitExit()
        End If
                
        'Return the last Office KMS event containing containing the SKUID value for the installed KMS key.
        '& retrieve the CMID value from the event.
        oKmsEventCounter = 0
        eventCode = "12288"
        Set objEvents = objWMI.ExecQuery _
        ("Select * from Win32_NTLogEvent Where Logfile = 'Application' and " _
        & "EventCode = '" & eventCode & "'")
        If objEvents.Count > 0 Then
            For each objEvent in objEvents
                oKmsEvent = InStr(objEvent.Message,strSkuId)
                If oKmsEvent <> 0 Then
                    oKmsEventCounter = oKmsEventCounter + 1
                    parseEvntMsg1 = InStr(objEvent.Message, ", ")
                    parseEvntMsg2 = InStr(parseEvntMsg1 + 2,objEvent.Message, ", ")
                    parseEvntMsg3 = InStr(parseEvntMsg2 + 2,objEvent.Message, ", ")
                    parseEvntMsg4 = InStr(parseEvntMsg3 + 2,objEvent.Message, ", ") 
                    WScript.Echo MSG_CMID & Mid(objEvent.Message,parseEvntMsg3 + 2,parseEvntMsg4 - (parseEvntMsg3 + 2))
                    Exit For
                End If
            Next
        End If
        
        If oKmsEventCounter = 0 Then
            WScript.Echo MSG_CMID & MSG_CMID_NOTFOUND
        End If
    Else
        If objOspp.ClientMachineID <> "" Or objOspp.ClientMachineID <> Null Then
            WScript.Echo MSG_CMID & objOspp.ClientMachineID
        Else
            WScript.Echo MSG_CMID & MSG_CMID_NOTFOUND
        End If
    End If
    quitExit()

ElseIf strCommand = "/inslic" Then
    i = i + 1
    If Right(strValue,7) = ".xrm-ms" Then
        verifyFileExists strValue
        WScript.Echo MSG_INSTALLLICENSE & strValue
    Else
        globalPopFailure MSG_UNRECOGFILE,True
    End If
    LicenseData = ReadAllTextFile(strValue)
    objOSpp.InstallLicense(LicenseData)
    SppErrHandle(strCommand)
ElseIf strCommand = "/stokflag" Then
    i = i + 1
    If Win7 = True Then
        objOspp.DisableKeyManagementServiceActivation(True)
        sppErrHandle(strCommand)
    Else
        'Unsupported - osppsvc only supports this.
        globalPopFailure MSG_UNSUPPORTEDOPEROS7 & vbCr & strCommand,True
    End If
ElseIf strCommand = "/ctokflag" Then
    i = i + 1
    If Win7 = True Then
        objOspp.DisableKeyManagementServiceActivation(False)
        SppErrHandle(strCommand)
    Else
        'Unsupported - osppsvc only supports this.
        globalPopFailure MSG_UNSUPPORTEDOPEROS7 & vbCr & strCommand,True
    End If
ElseIf strCommand = "/dtokils" Then
    Err.Clear
    Set objWmiDate = CreateObject("WBemScripting.SWbemDateTime")
    ExecuteQuery "ILID, ILVID, AuthorizationStatus, ExpirationDate, Description, AdditionalInfo","",tokenClass
    
    For Each instance in productinstances
        sppErrHandle ""
        i = i + 1
        WScript.Echo "License ID (ILID): " & instance.ILID
        WScript.Echo "Version ID (ILvID): " & instance.ILVID
        If Not IsNull(instance.ExpirationDate) Then
            objWmiDate.Value = instance.ExpirationDate
            If (objWmiDate.GetFileTime(false) <> 0) Then
                WScript.Echo "Expiry Date: " & objWmiDate.GetVarDate
            End If
        End If
        If Not IsNull(instance.AdditionalInfo) Then
            WScript.Echo "Additional Info: " & instance.AdditionalInfo
        End If
        If Not IsNull(instance.AuthorizationStatus) And instance.AuthorizationStatus <> 0 Then
            globalErr = CStr(Hex(instance.AuthorizationStatus))
            WScript.Echo MSG_AUTHERR & globalErr
            quitExit()
        Else            
            WScript.Echo "Description: " & instance.Description
        End If
        WScript.Echo MSG_SEPERATE
    Next
    If i = 0 Then
        WScript.Echo MSG_NOLICENSEFOUND
    End If
    quitExit()
ElseIf strCommand = "/rtokil" Then
    Err.Clear    
    ExecuteQuery "ILID, ID","",tokenClass
    
    For Each instance in productinstances
        sppErrHandle ""
        i = i + 1
        If LCase(strValue) = LCase(instance.ILID) Then
            instance.Uninstall
            SppErrHandle(strCommand)
        Else
            WScript.Echo MSG_NOTFOUNDILID & strValue & " Run /dtokils to display the ILID for installed licenses."
        End If
    Next
    If i = 0 Then
        WScript.Echo MSG_NOLICENSEFOUND
    End If
    quitExit()
ElseIf strCommand = "/dtokcerts" Then
    Err.Clear
    Set objSigner = TkaGetSigner()
    sppErrHandle(strCommand)
    ExecuteQuery "ID, Name, ApplicationId, PartialProductKey, Description, LicenseIsAddon ","ApplicationId = '" & OfficeAppId & "' " & "AND PartialProductKey <> NULL " & "AND LicenseIsAddon = FALSE",productClass
    
    For each instance in productinstances
        i = i + 1
        sppErrHandle ""
        iRet = instance.GetTokenActivationGrants(arrGrants)
        If Err.Number = 0 Then
            arrThumbprints = objSigner.GetCertificateThumbprints(arrGrants)
            If Err.Number = 0 Then
                For Each strThumbprint in arrThumbprints
                    TkaPrintCertificate strThumbprint
                Next
            Else
                sppErrHandle ""
            End If
        Else
            sppErrHandle ""
        End If
        WScript.Echo MSG_SEPERATE
        Err.Clear
    Next
ElseIf strCommand = "/tokact" Then
    Err.Clear
    Set objSigner = TkaGetSigner()
    sppErrHandle "/ignore"
    pos1 = InStr(strValue,":")
    If pos1 = 0 Then
        'PIN not passed
        strThumbprint = strValue
    Else
        'PIN passed
        strThumbprint = Left(strValue,pos1 - 1)
        strPin = Replace(strValue,strThumbprint & ":","")
    End If
    
    ExecuteQuery "ID, Name, ApplicationId, PartialProductKey, Description, LicenseIsAddon ","ApplicationId = '" & OfficeAppId & "' " & "AND PartialProductKey <> NULL " & "AND LicenseIsAddon = FALSE",productClass
    
    For each instance in productinstances
        i = i + 1
        sppErrHandle ""        
        WScript.Echo MSG_TOKACTATTEMPT 
        WScript.Echo MSG_SKUID & instance.ID
        WScript.Echo MSG_LICENSENAME & instance.Name
        WScript.Echo MSG_DESCRIPTION & instance.Description
        WScript.Echo MSG_PARTIALKEY & instance.PartialProductKey
        iRet = instance.GenerateTokenActivationChallenge(strChallenge)
        If Err.Number = 0 Then
            strAuthInfo1 = objSigner.Sign(strChallenge, strThumbprint, strPin, strAuthInfo2)
            If Err.Number = 0 Then
                iRet = instance.DepositTokenActivationResponse(strChallenge, strAuthInfo1, strAuthInfo2)
                SppErrHandle(strCommand)
            Else
                sppErrHandle ""
            End If
        Else
            sppErrHandle ""
        End If
        WScript.Echo MSG_SEPERATE
    Next
Else
    Err.Clear
    If strCommand = "/dstatus" Or strCommand = "/dstatusall" Or strCommand = "/dpid" Or strCommand = "/dstatussub" Or strCommand = "/pstatus" Then
        If Win7 = True Then
            ExecuteQuery "ID, ApplicationId, EvaluationEndDate, PartialProductKey, Description, Name, LicenseStatus, LicenseStatusReason, ProductKeyID, GracePeriodRemaining, DiscoveredKeyManagementServiceMachineName, DiscoveredKeyManagementServiceMachinePort, VLActivationInterval, VLRenewalInterval, KeyManagementServiceMachine, KeyManagementServicePort, ProductKeyID2","ApplicationId = '" & OfficeAppId & "' ",productClass
        Else
            ExecuteQuery "ID, ApplicationId, EvaluationEndDate, PartialProductKey, Description, Name, LicenseStatus, LicenseStatusReason, ProductKeyID, GracePeriodRemaining, KeyManagementServiceLookupDomain, VLActivationType, ADActivationObjectName, ADActivationObjectDN, ADActivationCsvlkPid, ADActivationCsvlkSkuId, VLActivationTypeEnabled, DiscoveredKeyManagementServiceMachineName, DiscoveredKeyManagementServiceMachinePort, VLActivationInterval, VLRenewalInterval, KeyManagementServiceMachine, KeyManagementServicePort, ProductKeyID2","ApplicationId = '" & OfficeAppId & "' ",productClass    
        End If
    ElseIf strCommand = "/act" Or strCommand = "/actsub" Or strCommand = "/actp" Then
        ExecuteQuery "ID, ApplicationId, PartialProductKey, Description, Name","ApplicationId = '" & OfficeAppId & "' " & "AND PartialProductKey <> NULL ",productClass
    ElseIf strCommand = "/unpkey" Then
        ExecuteQuery "ID, ApplicationId, Description, PartialProductKey, Name, ProductKeyID","ApplicationId = '" & OfficeAppId & "' " & "AND PartialProductKey <> NULL ",productClass
        
    ElseIf strCommand = "/dinstid" Or strCommand = "/actcid" Then
        ExecuteQuery "ID, ApplicationId, Description, PartialProductKey, Name, OfflineInstallationId","ApplicationId = '" & OfficeAppId & "' " & "AND PartialProductKey <> NULL ",productClass
    ElseIf strCommand = "/actype" Or strCommand = "/skms-domain" Or strCommand = "/ckms-domain" Then
        If Win7 = True Then
             'Unsupported - sppsvc only supports this.
            globalPopFailure MSG_UNSUPPORTEDOPEROS8 & vbCr & strCommand,True
        Else
            ExecuteQuery "ID, Description, PartialProductKey, ApplicationId ","ApplicationId = '" & OfficeAppId & "' ",productClass
        End If
    ElseIf strCommand = "/sethst" Or strCommand = "/setprt" Or strCommand = "/remhst" Then
        ExecuteQuery "ID, Description, PartialProductKey, ApplicationId ","ApplicationId = '" & OfficeAppId & "' ",productClass
    End If
            
    For Each instance in productinstances
        sppErrHandle ""
        If (LCase(instance.ApplicationId) = OfficeAppId) Then
            If instance.PartialProductKey <> "" Then
                i = i + 1
            End If
            intIsKms = InStr(UCase(instance.Description),"KMS")
            If intIsKms <> 0 Then
                kmsCounter = kmsCounter + 1
            End If
            Select Case strCommand
                Case "/actype"
                    Select Case strValue
                        Case "0","1","2","3"
                        Case Else
                            globalPopFailure MSG_UNSUPPORTED & " A value of" & vbCr &  _
                            "0  (for all)" & vbCr & "1  (for AD)" & vbCr & "2  (for KMS" & vbCr & _
                            "3  (for Token)" & vbCr & "Is required for: " & strCommand,True
                    End Select
                    If intIsKms <> 0 Then
                        If strValue <> 0 Then                    
                            instance.SetVLActivationTypeEnabled(strValue)
                        Else
                            instance.ClearVLActivationTypeEnabled()
                        End If
                    End If
                    sppErrHandle ""
                Case "/skms-domain"
                    If intIsKms <> 0 Then
                        instance.SetKeyManagementServiceLookupDomain(strValue)
                    End If
                    sppErrHandle ""
                Case "/ckms-domain"
                    If intIsKms <> 0 Then
                        instance.ClearKeyManagementServiceLookupDomain()
                    End If
                    sppErrHandle ""
                Case "/sethst"
                    If intIsKms <> 0 Then
                        instance.SetKeyManagementServiceMachine(strValue)
                    End If
                    sppErrHandle ""
                Case "/setprt"
                    If intIsKms <> 0 Then
                        instance.SetKeyManagementServicePort(strValue)
                    End If
                    sppErrHandle ""
                Case "/remhst"
                    If intIsKms <> 0 Then
                        instance.ClearKeyManagementServiceMachine()
                        sppErrHandle ""
                        instance.ClearKeyManagementServicePort()
                        sppErrHandle ""
                    End If
                Case "/act"
                    WScript.Echo MSG_ACTATTEMPT 
                    WScript.Echo MSG_SKUID & instance.ID
                    WScript.Echo MSG_LICENSENAME & instance.Name
                    WScript.Echo MSG_DESCRIPTION & instance.Description
                    WScript.Echo MSG_PARTIALKEY & instance.PartialProductKey            
                    instance.Activate
                    SppErrHandle(strCommand)
                    WScript.Echo MSG_SEPERATE
                Case "/unpkey"
                    If Len(strValue) <> "5" Then
                        globalPopFailure MSG_ERRPARTIALKEY,True
                    End If
                    If UCase(strValue) = instance.PartialProductKey Then
                        y = y + 1
                        WScript.Echo MSG_UNINSTALLKEY & instance.Name
                        instance.UninstallProductKey(instance.ProductKeyID)                            
                        SppErrHandle(strCommand)
                    End If
                Case "/dinstid"
                    WScript.Echo "Installation ID for: " & instance.Name & ": " & instance.OfflineInstallationId
                    WScript.Echo MSG_SEPERATE
                Case "/actcid"
                    instance.DepositOfflineConfirmationId instance.OfflineInstallationId, strValue
                    If Err.Number = 0 Then
                        If telsuccess <> True Then
                            WScript.Echo MSG_LICENSENAME & instance.Name
                            WScript.Echo MSG_OFFLINEACTSUCCESS
                            telsuccess = True
                        End If
                    Else
                        WScript.Echo MSG_LICENSENAME & instance.Name
                        sppErrHandle ""
                    End If
                    WScript.Echo MSG_SEPERATE
                Case "/dpid"
                    If instance.ProductKeyID <> "" Then
                        intOccurSub = InStr(LCase(instance.Name),"_sub")
                        intOccurPerp = InStr(LCase(instance.Name),"_retail") Or InStr(LCase(instance.Name),"_perp")
                        If intOccurSub <> 0 Or intOccurPerp <> 0 Then
                            WScript.Echo MSG_SEPERATE
                            If intOccurSub <> 0 Then 
                                foundSubKey = True
                                WScript.Echo MSG_KEYSINSTALLED_SUB
                            End If
                            If intOccurPerp <> 0 Then 
                                foundPerpKey = True
                                WScript.Echo MSG_KEYSINSTALLED_PERP
                            End If
                            WScript.Echo MSG_SEPERATE
                            WScript.Echo MSG_SKUID & UCase(instance.ID)
                            WScript.Echo MSG_LICENSENAME & instance.Name
                            WScript.Echo MSG_PARTIALKEY & instance.PartialProductKey 
                            WScript.Echo MSG_PID & instance.ProductKeyID2
                            'Determine machinekey from PID
                            strPid2 = Replace(instance.ProductKeyID2,"-","")
                            strPid2 = Right(strPid2,19)
                            strGid = Mid(strPid2,1,5)
                            strSerial1 = Mid(strPid2,6,3)
                            strSerial2 = Mid(strPid2,9,6)
                            WScript.Echo "Machine Key: " & strGid & "-" & strSerial1 & "-" & strSerial2
                        End If
                    End If
                Case "/dstatus", "/dstatusall"
                    getInstalled = False
                    verifyFileExists currentDir & "slerror.xml"
                    licSr = Hex(instance.LicenseStatusReason)
                    If strCommand = "/dstatusall" Then
                        getInstalled = True
                        WScript.Echo MSG_SKUID & instance.ID
                        WScript.Echo MSG_LICENSENAME & instance.Name
                        WScript.Echo MSG_DESCRIPTION & instance.Description            
                    Else
                        If instance.ProductKeyID <> "" Then
                            getInstalled = True
                            WScript.Echo MSG_PID & instance.ProductKeyID2                                                        
                            WScript.Echo MSG_SKUID & instance.ID
                            WScript.Echo MSG_LICENSENAME & instance.Name
                            WScript.Echo MSG_DESCRIPTION & instance.Description
                            'EvaluationEndDate always returns a value. When an expiry date is not defined "1/1/1601" is returned.
                            'So avoid displaying this against RTM licenses as that date = no expiry defined.
                            If instance.EvaluationEndDate <> "" Then
                                Set objDate = CreateObject("WBemScripting.SWbemDateTime")
                                objDate.Value = instance.EvaluationEndDate
                                If objDate.GetVarDate() <> "1/1/1601" Then
                                    WScript.Echo MSG_LICEXPIRY & objDate.GetVarDate()
                                End If
                                Set objDate = Nothing
                            End If
                         End If
                    End If
                    
                    If getInstalled = True Then
                        Select Case instance.LicenseStatus
                            Case 0
                                WScript.Echo MSG_LICSTATUS & MSG_UNLICENSED
                            Case 1
                                WScript.Echo MSG_LICSTATUS & MSG_LICENSED
                            Case 2
                                WScript.Echo MSG_LICSTATUS & MSG_OOBGRACE        
                            Case 3
                                WScript.Echo MSG_LICSTATUS & MSG_OOTGRACE
                            Case 4
                                WScript.Echo MSG_LICSTATUS & MSG_NONGENGRACE
                            Case 5
                                WScript.Echo MSG_LICSTATUS & MSG_NOTIFICATION
                            Case 6
                                WScript.Echo MSG_LICSTATUS & MSG_EXTENDEDGRACE    
                            Case Else
                                WScript.Echo MSG_LICSTATUS & MSG_LICUNKNOWN
                        End Select
                            
                        If licSr <> "0" Then
                            If instance.LicenseStatus <> 1 Then
                                WScript.Echo MSG_ERRCODE & "0x" & licSr
                            Else
                                WScript.Echo MSG_ERRCODE & "0x" & licSr & MSG_INFO_ONLY
                            End If
                            getResource("err" & "0x" & licSr)
                            If globalResource = "" Then
                                If foundSlUi <> True Then
                                    WScript.Echo MSG_ERRDESC & "Not available."
                                Else
                                    WScript.Echo MSG_ERRDESC & "Run the following: cscript ospp.vbs /ddescr:0x" & licSr
                                End if
                            Else
                                WScript.Echo MSG_ERRDESC & globalResource
                            End If
                        End If
                        
                        If instance.GracePeriodRemaining <> 0 Then
                            dGrace = instance.GracePeriodRemaining / 60 / 24
                            rndDown = Int(dGrace)
                            WScript.Echo MSG_REMAINGRACE & rndDown & " days " & " (" & instance.GracePeriodRemaining & " minute(s) before expiring" & ")"
                        End If
                            
                        If instance.PartialProductKey <> "" Then
                            WScript.Echo MSG_PARTIALKEY & instance.PartialProductKey
                            'Display additional volume info for KMS licenses
                            If intIsKms <> 0 Then
                                'Display activation type set (Win8+).
                                If Win7 <> True Then
                                    Select Case instance.VLActivationTypeEnabled
                                        Case 1
                                            WScript.Echo MSG_VLActivationType & "AD"
                                        Case 2
                                            WScript.Echo MSG_VLActivationType & "KMS"
                                        Case 3
                                            WScript.Echo MSG_VLActivationType & "Token"
                                        Case Else
                                            WScript.Echo MSG_VLActivationType & "ALL"
                                    End Select
                                    
                                    'Check to see if last activated via AD- display object info (Win8+).
                                    If instance.VLActivationType = 1 Then
                                        isAdActivated = True
                                        WScript.Echo MSG_Act_Recent + "AD"
                                        WScript.Echo vbTab & MSG_ADInfoAOName & instance.ADActivationObjectName
                                        WScript.Echo vbTab & MSG_ADInfoAODN & instance.ADActivationObjectDN
                                        WScript.Echo vbTab & MSG_ADInfoExtendedPid & instance.ADActivationCsvlkPid
                                        WScript.Echo vbTab & MSG_ADInfoActID & instance.ADActivationCsvlkSkuId
                                    End If
                                End If
                                
                                If isAdActivated = False Then
                                    strKms = instance.DiscoveredKeyManagementServiceMachineName
                                    strPort = instance.DiscoveredKeyManagementServiceMachinePort
                                        
                                    If IsNull(strKms) Or (strKms = "") Or IsNull(strPort) Or (strPort = 0) Then
                                        WScript.Echo vbTab & MSG_KMS_DNS_ERR
                                    Else
                                        WScript.Echo vbTab & MSG_KMS_DNS & strKMS & ":" & strPort
                                    End If
                                    
                                    'Check to see if registry override is defined
                                    strKms = instance.KeyManagementServiceMachine
                                    If strKms <> "" And Not IsNull(strKms) Then
                                         strPort = instance.KeyManagementServicePort
                                        If (strPort = 0) Then
                                            strPort = MSG_DEFAULT_PORT
                                        End If
                                        WScript.Echo vbTab & MSG_HOST_REG_OVERRIDE & strKms & ":" & strPort
                                    End If
                                        
                                    WScript.Echo vbTab & MSG_ACTIVATION_INTERVAL & instance.VLActivationInterval & " minutes"
                                    WScript.Echo vbTab & MSG_RENEWAL_INTERVAL & instance.VLRenewalInterval & " minutes"
                                        
                                     If (objOspp.KeyManagementServiceHostCaching = True) Then
                                        WScript.Echo vbTab & MSG_HOST_CACHING & "Enabled"
                                    Else
                                        WScript.Echo vbTab & MSG_HOST_CACHING & "Disabled"
                                    End If
                                    
                                    If Win7 <> True Then     
                                        If instance.KeyManagementServiceLookupDomain <> "" Then
                                            WScript.Echo vbTab & MSG_KMSLOOKUP & instance.KeyManagementServiceLookupDomain
                                        End If
                                    End If
                                End If                               
                            End If
                        End If
                        WScript.Echo MSG_SEPERATE
                    End If
                Case "/actsub","/actp"
                	intOccurSub=0
                    intOccurPerp=0
                    intOccurProduct=0
                    
                    If strCommand = "/actsub" Then
                        intOccurSub = InStr(LCase(instance.Name),"_sub")
                    Else
                        intOccurSub = InStr(LCase(instance.Name),"_sub")
                        intOccurPerp = InStr(LCase(instance.Name),"_retail") Or InStr(LCase(instance.Name),"_perp")
                        If intOccurSub <> 0 Or intOccurPerp <> 0 Then
                            intOccurProduct = InStr(LCase(instance.Name),strValue)
                        End If
                    End If

                    If strCommand = "/actsub" And intOccurSub <> 0 Or intOccurProduct <> 0 Then
                        foundCssKey = True
                        WScript.Echo MSG_ACTATTEMPT 
                        WScript.Echo MSG_SKUID & instance.ID
                        WScript.Echo MSG_LICENSENAME & instance.Name
                        WScript.Echo MSG_DESCRIPTION & instance.Description
                        WScript.Echo MSG_PARTIALKEY & instance.PartialProductKey
                        instance.Activate
                        sppErrHandle(strCommand)
                        WScript.Echo MSG_SEPERATE
                    End If
                Case "/dstatussub","/pstatus"
                	intOccurSub=0
                    intOccurPerp=0
                    intOccurProduct=0
                    dlicense = True

                    verifyFileExists currentDir & "slerror.xml"
                    licSr = Hex(instance.LicenseStatusReason)
                    If instance.ProductKeyID <> "" Then
                        If strCommand = "/dstatussub" Then
                            intOccurSub = InStr(LCase(instance.Name),"_sub")
                        Else
                            intOccurSub = InStr(LCase(instance.Name),"_sub")
                            intOccurPerp = InStr(LCase(instance.Name),"_retail") Or InStr(LCase(instance.Name),"_perp")
                            If intOccurSub <> 0 Or intOccurPerp <> 0 Then
                                intOccurProduct = InStr(LCase(instance.Name),strValue)
                                If intOccurSub <> 0 And intOccurProduct <> 0 Then
                                	getHeartBeat = True
                                End If
                            End If
                        End If

                        If strCommand = "/dstatussub" And intOccurSub <> 0 Or intOccurProduct <> 0 Then
                            foundCssKey = True
                            WScript.Echo MSG_PID & instance.ProductKeyID2
                            WScript.Echo MSG_SKUID & instance.ID
                            WScript.Echo MSG_LICENSENAME & instance.Name
                            WScript.Echo MSG_DESCRIPTION & instance.Description
                            'EvaluationEndDate always returns a value. When an expiry date is not defined "1/1/1601" is returned.
                            'So avoid displaying this against RTM licenses as that date = no expiry defined.
                            If instance.EvaluationEndDate <> "" Then
                                Set objDate = CreateObject("WBemScripting.SWbemDateTime")
                                objDate.Value = instance.EvaluationEndDate
                                If objDate.GetVarDate() <> "1/1/1601" Then
                                    WScript.Echo MSG_LICEXPIRY & objDate.GetVarDate()
                                End If
                                Set objDate = Nothing
                            End If

                            Select Case instance.LicenseStatus
                                Case 0
                                    WScript.Echo MSG_LICSTATUS & MSG_UNLICENSED
                                Case 1
                                    WScript.Echo MSG_LICSTATUS & MSG_LICENSED
                                Case 2
                                    WScript.Echo MSG_LICSTATUS & MSG_OOBGRACE
                                Case 3
                                    WScript.Echo MSG_LICSTATUS & MSG_OOTGRACE
                                Case 4
                                    WScript.Echo MSG_LICSTATUS & MSG_NONGENGRACE
                                Case 5
                                    WScript.Echo MSG_LICSTATUS & MSG_NOTIFICATION
                                Case 6
                                    WScript.Echo MSG_LICSTATUS & MSG_EXTENDEDGRACE
                                Case Else
                                    WScript.Echo MSG_LICSTATUS & MSG_LICUNKNOWN
                            End Select

                            If licSr <> "0" Then
                                If instance.LicenseStatus <> 1 Then
                                    WScript.Echo MSG_ERRCODE & "0x" & licSr
                                Else
                                    WScript.Echo MSG_ERRCODE & "0x" & licSr & MSG_INFO_ONLY
                                End If

                                getResource("err" & "0x" & licSr)
                                If globalResource = "" Then
                                    If foundSlUi <> True Then
                                       WScript.Echo MSG_ERRDESC & "Not available."
                                    Else
                                        WScript.Echo MSG_ERRDESC & "Run the following: cscript ospp.vbs /ddescr:0x" & licSr
                                    End if
                                Else
                                    WScript.Echo MSG_ERRDESC & globalResource
                                End If
                            End If

                            If instance.GracePeriodRemaining <> 0 Then
                                dGrace = instance.GracePeriodRemaining / 60 / 24
                                rndDown = Int(dGrace)
                                WScript.Echo MSG_REMAINGRACE & rndDown & " days " & " (" & instance.GracePeriodRemaining & " minute(s) before expiring" & ")"
                            End If

                            If instance.PartialProductKey <> "" Then
                                WScript.Echo MSG_PARTIALKEY & instance.PartialProductKey
                            End If

                            'Determine machinekey from PID
                            strPid2 = Replace(instance.ProductKeyID2,"-","")
                            strPid2 = Right(strPid2,19)
                            strGid = Mid(strPid2,1,5)
                            strSerial1 = Mid(strPid2,6,3)
                            strSerial2 = Mid(strPid2,9,6)
                            WScript.Echo "MACHINE KEY: " & strGid & "-" & strSerial1 & "-" & strSerial2
                            WScript.Echo MSG_SEPERATE
                         End If
                    End If
                Case Else
            End Select
        End If
    Next
End If

Select Case strCommand
    Case "/unpkey"
        If y = 0 Then
            WScript.Echo MSG_KEYNOTFOUND
            quitExit()
        End If
    Case "/ckms-domain","/skms-domain","/actype","/sethst","/setprt","/remhst"
        If kmsCounter = 0 Then
            WScript.Echo MSG_NOKMSLICS
            quitExit()
        Else
            sppErrHandle(strCommand)
        End If
    Case Else
End Select

If strCommand <> "/dpid" Then
    If strCommand = "/actsub" Or strCommand = "/dstatussub" Or strCommand = "/actp" Or strCommand = "/pstatus" Then
        If foundCssKey <> True Then
            WScript.Echo MSG_NOKEYSINSTALLED
            WScript.Echo MSG_SEPERATE
        End If
    Else
        If i = 0 Then
            WScript.Echo MSG_NOKEYSINSTALLED
            WScript.Echo MSG_SEPERATE
        End If
    End If
Else
    If foundSubKey <> True Then
        WScript.Echo MSG_SEPERATE
        WScript.Echo MSG_NOKEYSINSTALLED_SUB
        WScript.Echo MSG_SEPERATE
    End If
    If foundPerpKey <> True Then
        WScript.Echo MSG_SEPERATE
        WScript.Echo MSG_NOKEYSINSTALLED_PERP
        WScript.Echo MSG_SEPERATE
    End If
End If

If dlicense = False Then quitExit()

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function performRegAction(strCommand)

On Error Resume Next

If Win7 = True Then
    Set colListOfServices = objWMI.ExecQuery _
        ("Select * from Win32_Service ")
    For Each objService in colListOfServices
        If objService.Name = "osppsvc" Then
            installed = True
            Exit For
        End If
    Next
        
    If installed <> True Then
        globalPopFailure MSG_OSPPSVC_NOINSTALL,True
    End If
    checkRegRights objWMI1,REG_OSPP
Else
    checkRegRights objWMI1,REG_SPP
End If

Select Case strCommand
    Case "/puserops"
        setRegValue objWMI1,"1","UserOperations"
    Case "/duserops"
        setRegValue objWMI1,"0","UserOperations"
End Select

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function performServiceAction(strCommand)

On Error Resume Next

Set colListOfServices = objWMI.ExecQuery _
    ("Select * from Win32_Service ")
For Each objService in colListOfServices
    If objService.Name = "osppsvc" Then
        installed = True
        Exit For
    End If
Next
    
If installed <> True Then
    globalPopFailure MSG_OSPPSVC_NOINSTALL,True
End If

Set objService = Nothing
Set colListOfServices = Nothing

If strCommand = "/osppsvcauto" Then
    Set colListOfServices = objWMI.ExecQuery _
        ("Select * from Win32_Service where StartMode = 'Manual' or StartMode = 'Disabled'")
        For Each objService in colListOfServices
            If LCase(objService.Name) = "osppsvc" Then
                foundOsppNonAuto = True
                objService.Change , , , , "Automatic"
                WScript.Sleep(15000)
                Exit For
            End If
        Next
        If foundOsppNonAuto <> True Then
            WScript.Echo "Service startup type already set to automatic: Office Software Protection Platform"
            quitExit()
        End If
        
        Set objService = Nothing
        Set colListOfServices = Nothing
        Set colListOfServices = objWMI.ExecQuery _
        ("Select * from Win32_Service where StartMode = 'Auto'")
        For Each objService in colListOfServices
            If LCase(objService.Name) = "osppsvc" Then
                foundOsppAuto = True
                WScript.Echo "Successfully set service startup to automatic:" & objService.DisplayName
                quitExit()
            End If
        Next
        
        If foundOsppAuto <> True Then
            WScript.Echo "Unsuccessful setting service startup to automatic. " & MSG_ISCMD_ELEVATED
            quitExit()
        End If
Else
    Set colListOfServices = objWMI.ExecQuery _
        ("Select * from Win32_Service ")
    For Each objService in colListOfServices
        If LCase(objService.Name) = "osppsvc" Then
            Select Case LCase(objService.State)
                Case "running"
                    objService.StopService()
                    WScript.Sleep(15000)
                    objService.StartService()
                    WScript.Sleep(15000)
                Case Else
                    objService.StartService()
                    WScript.Sleep(15000)
            End Select
            Exit For
        End If
    Next
    
    Set objService = Nothing
    Set colListOfServices = Nothing
    Set colListOfServices = objWMI.ExecQuery _
        ("Select * from Win32_Service ")
    For Each objService in colListOfServices
        If LCase(objService.Name) = "osppsvc" Then
            If LCase(objService.State) = "running" Then
                WScript.Echo "Successfully restarted: " & objService.DisplayName
                quitExit()
            Else
                WScript.Echo "Unsuccessful restart: " & objService.DisplayName & ". Status: " _
                    & objService.State & ". " & MSG_ISCMD_ELEVATED
                quitExit()
            End If
            Exit For
        End If
    Next
End If

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function reARM(skuid)

progFiles = WshShell.ExpandEnvironmentStrings("%ProgramFiles%")

If objFSO.FileExists(progFiles & STR_OSPPREARMPATH) Then
    rearmPath = progFiles & STR_OSPPREARMPATH
ElseIf objFSO.FileExists(progFiles & STR_OSPPREARMPATH_DEBUG) Then
    rearmPath = progFiles & STR_OSPPREARMPATH_DEBUG
Else
    progFilesX86 = WshShell.ExpandEnvironmentStrings("%ProgramFiles(x86)%")
    If objFSO.FileExists(progFilesX86 & STR_OSPPREARMPATH) Then
        rearmPath = progFilesX86 & STR_OSPPREARMPATH
    ElseIf objFSO.FileExists(progFilesX86 & STR_OSPPREARMPATH_DEBUG) Then
        rearmPath = progFilesX86 & STR_OSPPREARMPATH_DEBUG
    Else
        WScript.Echo MSG_FILENOTFOUND & "OSPPREARM.EXE"
        quitExit()
    End If
End If

If skuid = "" Then   
    Set objScriptExec = WshShell.Exec (rearmPath)
Else
    Set objScriptExec = WshShell.Exec (rearmPath & " " & skuid)
End If

readOut = objScriptExec.StdOut.ReadAll
WScript.Echo readOut
    
End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function setWinOS()

Set colOperatingSystems = objWMI.ExecQuery _
        ("Select * from Win32_OperatingSystem")
    For Each objOperatingSystem in colOperatingSystems
        Ver = Split(objOperatingSystem.Version, ".", -1, 1)
        ' Win7/Server2008R2
         If (Ver(0) = "6" And Ver(1) = "1") Then
            Win7 = True
            Exit For
         End If
            
         ' Win8/Server2012
        If (Ver(0) = "6" And Ver(1) = "2") Then
            Win8 = True
            Exit For
        End If
    Next

setWmiClasses()

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function setWmiClasses()

If Win7 = True Then
    productClass = "OfficeSoftwareProtectionProduct"
    tokenClass = "OfficeSoftwareProtectionTokenActivationLicense"
Else
    productClass = "SoftwareLicensingProduct"
    tokenClass = "SoftwareLicensingTokenActivationLicense"
End If

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function getEvents(strMessage,strLog,strEventCode,strSource,strMachine)
       
WScript.Echo MSG_SEARCHFOR & strMessage & "<<<<< Log: " & strLog & "  Source: " & strSource & "  Event: " & strEventCode & " >>>>>" 
WScript.Echo MSG_SEPERATE

Set objEvents = objWMI.ExecQuery _
    ("Select * from Win32_NTLogEvent Where Logfile = '" & strLog &  "'" & " and "_
    & "EventCode = '" & strEventCode & "'" & " and SourceName = '" & strSource & "'")
        
If objEvents.Count > 0 Then
    WScript.Echo MSG_SEPERATESMALL
    For each objEvent in objEvents
        dtmEventDate = objEvent.TimeWritten
        strTimeWritten = WMIDateStringToDate(dtmEventDate)
        WScript.Echo "Coordinated Universal Time Written: " & strTimeWritten
        WScript.Echo objEvent.Message
        WScript.Echo MSG_SEPERATESMALL
    Next
    WScript.Echo MSG_SEPERATE
Else
    WScript.Echo MSG_NOEVENTS
    WScript.Echo MSG_SEPERATE
End If 

Set objEvents = Nothing
        
End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function getMachineId(strMachine)

Set objInstances = objWMI.InstancesOf("Win32_ComputerSystemProduct")

For Each objInstance in objInstances
    WScript.Echo "MachineID: " & objInstance.uuid
    WScript.Echo MSG_SEPERATE
Next

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
Function getHeartbeatXml(strMachine)

On Error Resume Next

If strMachine <> "" Then
    WScript.Echo MSG_HEARTBEAT_LOCALONLY
Else
    If objFSO.FileExists(CreateObject("Shell.Application").Namespace(&H23&).Self.Path & STR_HEARTBEATPATH) Then
        fHeartBeat = True
        Set MyXmlDoc = CreateObject("Msxml2.DOMDocument.6.0") 
        MyXmlDoc.load(CreateObject("Shell.Application").Namespace(&H23&).Self.Path & STR_HEARTBEATPATH)
        WScript.Echo "HeartbeatCache.xml found: " & CreateObject("Shell.Application").Namespace(&H23&).Self.Path & STR_HEARTBEATPATH
        WScript.Echo "Contents:"
        WScript.Echo MSG_SEPERATESMALL
        Set nodes = MyXmlDoc.selectNodes("//*")
        For i = 0 to nodes.length - 1
            If LCase(nodes(i).nodeName) <> "heartbeatcache" Then
                'lastchk & skuid are attribs of License node
                If LCase(nodes(i).nodeName) = "license" Then
                    hLastChk = nodes(i).attributes.getNamedItem("lastCheckTime").text
                    WScript.Echo "lastCheckTime: " & hLastChk
                    hSkuId = nodes(i).attributes.getNamedItem("skuId").text
                    WScript.Echo "skuId: " & hSkuId
                Else
                    WScript.Echo nodes(i).nodeName & ": " & nodes(i).text
                End If
            End If
        Next
    End If
    
    If fHeartBeat <> True Then
        WScript.Echo MSG_FILENOTFOUND & "HeartbeatCache.xml"
    End If
    
End If
    
WScript.Echo MSG_SEPERATE

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
' Checks if there is a KB article for the specified error
Function lookupKBArticle(errorCode)
    If InStr(errorKBs, errorCode) > 0 Then
        WScript.Echo MSG_ACT_ERROR_FOUND_KB & "0x" & errorCode
        WScript.Echo MSG_ACT_ERROR_KB_LINK & errorCode
    End If
End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
'Checks the registry for any key that enables SCA and reports whether SCA
'is enabled or not by any of those keys.
Function checkScaStatus()
    WScript.Echo MSG_SEARCHFOR & MSG_SCAREGKEYS
    WScript.Echo MSG_SEPERATE

    Dim flavorsList
    Set flavorsList = CreateObject("System.Collections.ArrayList")

    flavorsList.Add(VALUE_SCAEXP_FLAVOR)
    flavorsList.Add(VALUE_SCAEXP_OVERRIDE_FLAVOR)
    flavorsList.Add(VALUE_SCAO15_FLAVOR)
    flavorsList.Add(VALUE_SCA016_FLAVOR)

    Dim result, flavor
    result = False
    For Each flavor in flavorsList
        result = result Or checkScaStatusForFlavor(flavor)
    Next

    If result = True Then
        WScript.Echo "Machine in SCA mode."
    Else
        WScript.Echo "Machine NOT in SCA mode."
    End If

End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
'Checks the registry for a particular key that enables SCA in one specific
'flavor and returns whether SCA is enabled or disabled. Flavors are SCA Experiment,
'SCA Experiment override, SCA for O15 and SCA for O16
Function checkScaStatusForFlavor(flavor)

    On Error Resume Next

    dim key, message, keyType, result

    Select Case flavor
        Case VALUE_SCAEXP_FLAVOR
            key =  REG_SCAEXP_BASE
            message = MSG_SCAEXP
            keyType = VALUE_SCAREGKEY_PER_APP_TYPE
        Case VALUE_SCAEXP_OVERRIDE_FLAVOR
            key = REG_SCAEXP_OVERRIDE
            message = MSG_SCAEXP_OVERRIDE
            keyType = VALUE_SCAREGKEY_SINGLE_TYPE
        Case VALUE_SCAO15_FLAVOR
            key = REG_SCAO15
            message = MSG_SCAO15
            keyType = VALUE_SCAREGKEY_SINGLE_TYPE
        Case VALUE_SCA016_FLAVOR
            key = REG_SCAO16
            message = MSG_SCAO16
            keyType = VALUE_SCAREGKEY_SINGLE_TYPE
        Case Else
    End Select

    result = False
    If (keyType = VALUE_SCAREGKEY_SINGLE_TYPE) Then
        result = readAndReportScaKey(key, message)
    ElseIf (keyType = VALUE_SCAREGKEY_PER_APP_TYPE) Then
        Dim appsList
        Set appsList = CreateObject("System.Collections.ArrayList")

        appsList.Add("word")
        appsList.Add("excel")
        appsList.Add("powerpoint")
        appsList.Add("visio")
        appsList.Add("project")
        appsList.Add("onenote")
        appsList.Add("outlook")
        appsList.Add("access")
        appsList.Add("publisher")
        appsList.Add("lync")

        Dim app, keyPerApp
        For Each app In appsList
            keyPerApp = key & app & REG_SCAEXP_END
            result = result Or readAndReportScaKey(keyPerApp, message)
        Next
    End If

    checkScaStatusForFlavor = result
End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////
'Reads the registry looking for a SCA key and if found reports whether or not
'that key enables SCA.
Function readAndReportScaKey(key, message)

    On Error Resume Next

    Dim result, keyValue
    keyValue = WshShell.RegRead(key)

    If Err.Number = 0 Then
        If keyValue = 1 Then
            WScript.Echo message & MSG_SCAREGKEY_ACTIVE
            result = True
        Else
            WScript.Echo message & MSG_SCAREGKEY_INACTIVE
            result = False
        End If

        WScript.Echo key
        WScript.Echo MSG_SEPERATESMALL
    Else
        result = False
    End If
    Err.Clear

    readAndReportScaKey = result
End Function
'////////////////////////////////////////////////////////////////////////////////////////
'////////////////////////////////////////////////////////////////////////////////////////

'' SIG '' Begin signature block
'' SIG '' MIIlogYJKoZIhvcNAQcCoIIlkzCCJY8CAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' eRmuJTRxBA78Fz3WCj2JjTRm6cUMUZvuKsvOrf3TrTmg
'' SIG '' ggtyMIIE+jCCA+KgAwIBAgITMwAABJAOYRSYEngjcAAA
'' SIG '' AAAEkDANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJV
'' SIG '' UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
'' SIG '' UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
'' SIG '' cmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBT
'' SIG '' aWduaW5nIFBDQSAyMDEwMB4XDTIyMDUxMjIwNDcwNVoX
'' SIG '' DTIzMDUxMTIwNDcwNVowdDELMAkGA1UEBhMCVVMxEzAR
'' SIG '' BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
'' SIG '' bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
'' SIG '' bjEeMBwGA1UEAxMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
'' SIG '' kzKQ8vGa0bmAeZL9lDoj932a4dRNz0Kx3d8KQVWyoUu5
'' SIG '' KfbowT+sAi2YqzLiGxCaFmlb3NR3nOuLCPbkbHAszb1i
'' SIG '' e2jFFPegX9Pv5hi4m7kno19cQgSuugPWg0BqduLJjo9Y
'' SIG '' mYEwPFDxwqATz3OhczReOZSs4WYsPuS5iozdAzsRkyYa
'' SIG '' AqzEHaCbfjlqF2BuAfDVMNNUUTrWdTP3fu2zSlWOtMCu
'' SIG '' 3ZiarDD2e+A26rrhQfRNcCKpgIqKxZzuhE+dEsWDjS2l
'' SIG '' wGI4hGSvJUU+n8/q0gEEv5ihubVFUXA+Rbe+Ng2d9Na2
'' SIG '' 5n1L2wex6z3H+lfh8gNUl7OuooacTwk3SQIDAQABo4IB
'' SIG '' eTCCAXUwHwYDVR0lBBgwFgYKKwYBBAGCNz0GAQYIKwYB
'' SIG '' BQUHAwMwHQYDVR0OBBYEFB6A9Jmd73vEgtVXj6p5ztef
'' SIG '' OsgFMFAGA1UdEQRJMEekRTBDMSkwJwYDVQQLEyBNaWNy
'' SIG '' b3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEWMBQG
'' SIG '' A1UEBRMNMjMwODY1KzQ3MDU2MjAfBgNVHSMEGDAWgBTm
'' SIG '' /F97uyIAWORyTrX0IXQjMubvrDBWBgNVHR8ETzBNMEug
'' SIG '' SaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
'' SIG '' L2NybC9wcm9kdWN0cy9NaWNDb2RTaWdQQ0FfMjAxMC0w
'' SIG '' Ny0wNi5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
'' SIG '' BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
'' SIG '' L2NlcnRzL01pY0NvZFNpZ1BDQV8yMDEwLTA3LTA2LmNy
'' SIG '' dDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IB
'' SIG '' AQA+hWJ633NByB9VK8ZlZLCUq2e3X1MdTQe8D7aRgpeX
'' SIG '' yzMxP8Iapp0wDFvAgACtPXr0DBHleAK3yUhti1xo50f8
'' SIG '' YgQ+O/a/Tqqp5/TaHzvP5LfJU4Mm4DpSeMQU75/WXdyP
'' SIG '' wKxRZjD8FdsCelpWgrGa5eCW4lqYQILMpSLO555pSFBA
'' SIG '' QkrNB1BJtViE0ZzaH+0skTY15S5Zm3m0WEG7VdTCmwcy
'' SIG '' m1H+MzSZar4wC0XSGzXrd3bDmHJhkws9ORZaka/MlpHa
'' SIG '' 7LFGKTlfuZ1n1gLBcMx4P48NXB6F5ngq+yJZy1wxiI2W
'' SIG '' Vh2ymanlnw1a5cKjLH5+xJUk6nMHz47OmIEuMIIGcDCC
'' SIG '' BFigAwIBAgIKYQxSTAAAAAAAAzANBgkqhkiG9w0BAQsF
'' SIG '' ADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
'' SIG '' bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
'' SIG '' FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
'' SIG '' TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9y
'' SIG '' aXR5IDIwMTAwHhcNMTAwNzA2MjA0MDE3WhcNMjUwNzA2
'' SIG '' MjA1MDE3WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
'' SIG '' V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
'' SIG '' A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
'' SIG '' VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAy
'' SIG '' MDEwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
'' SIG '' AQEA6Q5kUHlntcTj/QkATJ6UrPdWaOpE2M/FWE+ppXZ8
'' SIG '' bUW60zmStKQe+fllguQX0o/9RJwI6GWTzixVhL99COMu
'' SIG '' K6hBKxi3oktuSUxrFQfe0dLCiR5xlM21f0u0rwjYzIjW
'' SIG '' axeUOpPOJj/s5v40mFfVHV1J9rIqLtWFu1k/+JC0K4N0
'' SIG '' yiuzO0bj8EZJwRdmVMkcvR3EVWJXcvhnuSUgNN5dpqWV
'' SIG '' XqsogM3Vsp7lA7Vj07IUyMHIiiYKWX8H7P8O7YASNUwS
'' SIG '' pr5SW/Wm2uCLC0h31oVH1RC5xuiq7otqLQVcYMa0Kluc
'' SIG '' IxxfReMaFB5vN8sZM4BqiU2jamZjeJPVMM+VHwIDAQAB
'' SIG '' o4IB4zCCAd8wEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0O
'' SIG '' BBYEFOb8X3u7IgBY5HJOtfQhdCMy5u+sMBkGCSsGAQQB
'' SIG '' gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
'' SIG '' BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP
'' SIG '' 6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeG
'' SIG '' RWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3Js
'' SIG '' L3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIz
'' SIG '' LmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKG
'' SIG '' Pmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
'' SIG '' dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGd
'' SIG '' BgNVHSAEgZUwgZIwgY8GCSsGAQQBgjcuAzCBgTA9Bggr
'' SIG '' BgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
'' SIG '' L1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEF
'' SIG '' BQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMA
'' SIG '' eQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG
'' SIG '' 9w0BAQsFAAOCAgEAGnTvV08pe8QWhXi4UNMi/AmdrIKX
'' SIG '' +DT/KiyXlRLl5L/Pv5PI4zSp24G43B4AvtI1b6/lf3mV
'' SIG '' d+UC1PHr2M1OHhthosJaIxrwjKhiUUVnCOM/PB6T+DCF
'' SIG '' F8g5QKbXDrMhKeWloWmMIpPMdJjnoUdD8lOswA8waX/+
'' SIG '' 0iUgbW9h098H1dlyACxphnY9UdumOUjJN2FtB91TGcun
'' SIG '' 1mHCv+KDqw/ga5uV1n0oUbCJSlGkmmzItx9KGg5pqdfc
'' SIG '' wX7RSXCqtq27ckdjF/qm1qKmhuyoEESbY7ayaYkGx0aG
'' SIG '' ehg/6MUdIdV7+QIjLcVBy78dTMgW77Gcf/wiS0mKbhXj
'' SIG '' pn92W9FTeZGFndXS2z1zNfM8rlSyUkdqwKoTldKOEdqZ
'' SIG '' Z14yjPs3hdHcdYWch8ZaV4XCv90Nj4ybLeu07s8n07Ve
'' SIG '' afqkFgQBpyRnc89NT7beBVaXevfpUk30dwVPhcbYC/GO
'' SIG '' 7UIJ0Q124yNWeCImNr7KsYxuqh3khdpHM2KPpMmRM19x
'' SIG '' HkCvmGXJIuhCISWKHC1g2TeJQYkqFg/XYTyUaGBS79ZH
'' SIG '' maCAQO4VgXc+nOBTGBpQHTiVmx5mMxMnORd4hzbOTsNf
'' SIG '' svU9R1O24OXbC2E9KteSLM43Wj5AQjGkHxAIwlacvyRd
'' SIG '' UQKdannSF9PawZSOB3slcUSrBmrm1MbfI5qWdcUxghmI
'' SIG '' MIIZhAIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEGA1UE
'' SIG '' CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
'' SIG '' MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgw
'' SIG '' JgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBD
'' SIG '' QSAyMDEwAhMzAAAEkA5hFJgSeCNwAAAAAASQMA0GCWCG
'' SIG '' SAFlAwQCAQUAoIHAMBkGCSqGSIb3DQEJAzEMBgorBgEE
'' SIG '' AYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3
'' SIG '' AgEVMC8GCSqGSIb3DQEJBDEiBCCTcpomHuBPzal5D/0K
'' SIG '' 8KUGWiFn++NkezkyXJ1inZcqkjBUBgorBgEEAYI3AgEM
'' SIG '' MUYwRKAigCAATQBpAGMAcgBvAHMAbwBmAHQAIABPAGYA
'' SIG '' ZgBpAGMAZaEegBxodHRwOi8vb2ZmaWNlLm1pY3Jvc29m
'' SIG '' dC5jb20gMA0GCSqGSIb3DQEBAQUABIIBAIcb7n04kONk
'' SIG '' HL1Znv3RmFWDaSJdC1/wse90WbSkV9x69VdkSnW/YXdh
'' SIG '' anIau5MpeZ9swF+qJxEVNdor0TxM1pu6J5ArY3Gxn62O
'' SIG '' Np0Bng9elm6Gu2ZIFGY4Vnp2Tsb8LlLsr3tPY3ovjT9V
'' SIG '' zyyHiypBICGufUi62MHmOXnzb0PztGeEdTL8LTKOy8zS
'' SIG '' Z3LqNZuQb623uUZtlWekKJpPphZ2+Nhib38V5JhiNwFq
'' SIG '' E3qrwL0hqzvIIQwgEfX1RCmGivARohNP8VOnNxsVLrij
'' SIG '' YAVUYOHuWbCWQ0wrxC+E3ONDLEVyeLdFCE9Jr9k1XSzq
'' SIG '' aNfPZFSxfR4xYMkVjfAcmLuhghcAMIIW/AYKKwYBBAGC
'' SIG '' NwMDATGCFuwwghboBgkqhkiG9w0BBwKgghbZMIIW1QIB
'' SIG '' AzEPMA0GCWCGSAFlAwQCAQUAMIIBUQYLKoZIhvcNAQkQ
'' SIG '' AQSgggFABIIBPDCCATgCAQEGCisGAQQBhFkKAwEwMTAN
'' SIG '' BglghkgBZQMEAgEFAAQgYd9FlRSC7qeY3oCfXm8NVmQO
'' SIG '' BIdV4cbw3M4RK7pMu+wCBmNs4oRNoRgTMjAyMjExMjkx
'' SIG '' NDMyMjEuNTc0WjAEgAIB9KCB0KSBzTCByjELMAkGA1UE
'' SIG '' BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
'' SIG '' BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
'' SIG '' b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
'' SIG '' ZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVz
'' SIG '' IFRTUyBFU046REQ4Qy1FMzM3LTJGQUUxJTAjBgNVBAMT
'' SIG '' HE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghFX
'' SIG '' MIIHDDCCBPSgAwIBAgITMwAAAcUDzc0hofTvOQABAAAB
'' SIG '' xTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzET
'' SIG '' MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
'' SIG '' bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
'' SIG '' aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
'' SIG '' cCBQQ0EgMjAxMDAeFw0yMjExMDQxOTAxMzJaFw0yNDAy
'' SIG '' MDIxOTAxMzJaMIHKMQswCQYDVQQGEwJVUzETMBEGA1UE
'' SIG '' CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
'' SIG '' MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUw
'' SIG '' IwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRp
'' SIG '' b25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpERDhD
'' SIG '' LUUzMzctMkZBRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
'' SIG '' bWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
'' SIG '' BQADggIPADCCAgoCggIBAKtIXbO9Hl9tye6WqaWil0Yc
'' SIG '' /k0+ySdzr1X9/jfHzacUbOY2OIRL9wVf8ORFl22XTuJt
'' SIG '' 8Y9NZUyP8Q5KvsrY7oj3vMRl7GcQ57b+y9RMzHeYyEqi
'' SIG '' fnmLvJIFdOepqrPHQaOecWTzz3MX+btfc59OGjEBeT11
'' SIG '' fwuGS0oxWvSBTXK4m3Tpt5Rlta0ERWto1LLqeoL+t+Ku
'' SIG '' VMB9PVhhrtM/PUW7W8jOeb5gYFlfHnem2Qma3KGCIzC/
'' SIG '' BUU7xpc56puh7cGXVzMCh092v5C1Ej4hgLKyIBM8+zaQ
'' SIG '' aXjrILPU68Mlk2QTWwcMiAApkN+I/rkeHrdoWZPjR+PS
'' SIG '' oRCcmA9vnTiGgxgdhFDRUmHMtTJILWbdXkagQdJvmD2M
'' SIG '' +x46HD8pCmDUGe07/s4JTn3womsdYzm9LuiGAuV9Sa/A
'' SIG '' ME3LGg8rt6gIcfHBUDfQw4IlWcPlERWfKMqA5OrCFdZ8
'' SIG '' ec2S8voTbWpHj1/Uu2PJ9alnwI6FzxOitP3W08POxDiS
'' SIG '' /wZSRnCqBU8ra9Mz4PzDSUm+n9mv8A5F6BghliYkKxk8
'' SIG '' Yzj/kfev5yCBtOXhNS6ZMthTnWDDweA4Vu7QXWWrrXqU
'' SIG '' 07koZoJ/hihEfAKANYEkpNRAuWV+HKaVZ4CaW5TAbvK/
'' SIG '' 7QoXx1XV74mOoQ0oR8EApmamXm4EmB5x5eLqxPuCumQv
'' SIG '' AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUVOq7OL9ZsTWB
'' SIG '' v67aS8K1cHpNBWswHwYDVR0jBBgwFoAUn6cVXQBeYl2D
'' SIG '' 9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0
'' SIG '' cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwv
'' SIG '' TWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIw
'' SIG '' MTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEF
'' SIG '' BQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
'' SIG '' aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1w
'' SIG '' JTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIw
'' SIG '' ADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0B
'' SIG '' AQsFAAOCAgEAjKjefH6zBzknHIivgnZ6+nSvH07IEA3m
'' SIG '' fW70IwrsTSCWSfdvsaXikQn916uO6nUcpJClJ2QunR4S
'' SIG '' 8LdX4cMosvy33VUPcn9YWGf0aU0vs9IZ2qCvj/yAwIlD
'' SIG '' Zt9jVy4QwbtD+Em/7gleIzrjVHJiYaaQUIEFYRcf+eyW
'' SIG '' JNSwnYyHnv/xq3H25ELYmKG/Tmvdw0o27A9Y6monBJ5H
'' SIG '' JVDf5hJvWbJwpwNfvzkA6f/EOHD3x/eCzOCel9DbTQXl
'' SIG '' csL1h9MLjGjicx4AywniVJBRPRxPLAQ1XnZo+szyQCPu
'' SIG '' 6My42KsO4uERW4krX1mUho8LfpSyUGUVlAnE92h2L06N
'' SIG '' WFg2bJKIVoO+8PXxdkG4jvQ356qGe0KMx4u0Yj6W44JC
'' SIG '' TAIa4aXk3/2rdnvfh2JCjm1JoDwKx9Vo4r8JtXez2FrG
'' SIG '' qy+7uambpN+hm9ZhE0taANl19/gt64Lc0aIT/PamVX+/
'' SIG '' ZVb45oN+DbSAiv6TJPfUgbrYIbYqRUjEHW11J0tqHi7f
'' SIG '' XCrr9TCbvoCfN6l0zZENkKocbTUb2xPUKpqiUMOVVv+E
'' SIG '' mc3taT18cjkzucg6vokSFLm6nkM5lHApIsjbgix1ofDi
'' SIG '' wiOZiDgtYi7VQ39pcPXlq6KcLuUgybU/2cKiFNam9lPj
'' SIG '' Y5DXI9YWzgwURC2k01nfdUSYlCPZ3CZBoP4wggdxMIIF
'' SIG '' WaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqG
'' SIG '' SIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
'' SIG '' CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
'' SIG '' MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIw
'' SIG '' MAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
'' SIG '' ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVa
'' SIG '' Fw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMw
'' SIG '' EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
'' SIG '' b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
'' SIG '' b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
'' SIG '' IFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
'' SIG '' MIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwH
'' SIG '' B9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa
'' SIG '' 4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZr
'' SIG '' BxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6
'' SIG '' xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv62
'' SIG '' 6GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlw
'' SIG '' aQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
'' SIG '' Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I
'' SIG '' 5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF80
'' SIG '' 3RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26o
'' SIG '' ElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuv
'' SIG '' XsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFz
'' SIG '' ymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMh
'' SIG '' XV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/Zc
'' SIG '' UlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgV
'' SIG '' GD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOC
'' SIG '' Ad0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYB
'' SIG '' BAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0G
'' SIG '' A1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNV
'' SIG '' HSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUF
'' SIG '' BwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
'' SIG '' b3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAww
'' SIG '' CgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
'' SIG '' YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMB
'' SIG '' Af8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186a
'' SIG '' GMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5t
'' SIG '' aWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWlj
'' SIG '' Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUF
'' SIG '' BwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5t
'' SIG '' aWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJB
'' SIG '' dXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQAD
'' SIG '' ggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+Tkdk
'' SIG '' eLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGh
'' SIG '' lBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6
'' SIG '' Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7nd
'' SIG '' n/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n
'' SIG '' 4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZ
'' SIG '' UnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA
'' SIG '' 0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
'' SIG '' xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+
'' SIG '' c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxko
'' SIG '' JLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmx
'' SIG '' aQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/
'' SIG '' tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM
'' SIG '' +Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rR
'' SIG '' nj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N
'' SIG '' 7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzjCCAjcCAQEw
'' SIG '' gfihgdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
'' SIG '' EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
'' SIG '' HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAj
'' SIG '' BgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
'' SIG '' bnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkREOEMt
'' SIG '' RTMzNy0yRkFFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
'' SIG '' ZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQAh
'' SIG '' ABr2F2SSu3FKOtvi7xGEBMe/56CBgzCBgKR+MHwxCzAJ
'' SIG '' BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
'' SIG '' DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
'' SIG '' ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
'' SIG '' dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEB
'' SIG '' BQUAAgUA5zBs7TAiGA8yMDIyMTEyOTE5MzUwOVoYDzIw
'' SIG '' MjIxMTMwMTkzNTA5WjB3MD0GCisGAQQBhFkKBAExLzAt
'' SIG '' MAoCBQDnMGztAgEAMAoCAQACAhIqAgH/MAcCAQACAhG7
'' SIG '' MAoCBQDnMb5tAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwG
'' SIG '' CisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMB
'' SIG '' hqAwDQYJKoZIhvcNAQEFBQADgYEAxfgbeDDSMcfJkzyf
'' SIG '' S8gsWpoUUDZxhatmCXOTbq+YLl3Iz00x14LgvKri5924
'' SIG '' Ntn9RYIhK/1/bEFJd9aDzSBSUiJBLi0ArU0svV6mKC+d
'' SIG '' yPgYoqabkxNE1z0dNfOWSq8rb32KR9yG0OHTOgnHyPGI
'' SIG '' DjlPf+jzofcPMP7w4cWqWAkxggQNMIIECQIBATCBkzB8
'' SIG '' MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
'' SIG '' bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
'' SIG '' cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
'' SIG '' b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAcUD
'' SIG '' zc0hofTvOQABAAABxTANBglghkgBZQMEAgEFAKCCAUow
'' SIG '' GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqG
'' SIG '' SIb3DQEJBDEiBCAVWoGkr7NV8gh7sJIgJBsKpBGrVWVl
'' SIG '' /p06nmZIoRmjJzCB+gYLKoZIhvcNAQkQAi8xgeowgecw
'' SIG '' geQwgb0EIBkBsZH2JHdMCvldPcDtLDvrJvIADMo+RLij
'' SIG '' 6rzUP3yxMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
'' SIG '' BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
'' SIG '' bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
'' SIG '' bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
'' SIG '' UENBIDIwMTACEzMAAAHFA83NIaH07zkAAQAAAcUwIgQg
'' SIG '' WVY2gPSOF0FWlICVWJu5vipH6sDOPA5LyJyz+uS5YfUw
'' SIG '' DQYJKoZIhvcNAQELBQAEggIAF3GpZTui+dc5ZpzBJWRk
'' SIG '' POZ+/Y8SGjxhORbbY9hd1+Jx6seJB8gV+HqSuPxc7l7u
'' SIG '' XyEETxHjNVFu+9pIOzu0KKfg4uRsc99bd4JY+G5kPyt0
'' SIG '' T0UN38C4iN+1kn3mOgPpQHc3pktV9sXFE/QTH2mZG63U
'' SIG '' B5TxMqSYlP63mrLM3ZoFczc2/ZgRRbaFMb4wmx5iINGO
'' SIG '' ZTfIWnlYMQFm4TDkoUWVVocAF4DFIuly1NOVMV+Oq4sa
'' SIG '' g4hzGz+MlW4H08B6Pu0iXeQ944SqP3BJEuLfxiXBvmZ+
'' SIG '' IiYSFHK7ivAFPNj+IsD+qlxeK9xWWnUzbjo02/PkiGVh
'' SIG '' //KfteWBcjqcTFKNNIVVv7yt4Je+I5WCOu/SFHxUI+Zl
'' SIG '' KRYAF6OiL0ot2Z+AuwQUj1lQ2iU3VhFmUi3p9IlF9noc
'' SIG '' OdedlSIU6wmEfFFduSJ6w7WalT2/26oKaazjhW3zgPRP
'' SIG '' RGkZht/KJvhv9DfjXrkx4u8YGWNnSIaAh1TlIkKGUN50
'' SIG '' jvM6tmX2zWds9BwH4uQJge7Hywav8OKkCTGjlnfqkD7t
'' SIG '' dMrLBp3iYFX1SjsagX9SwEMRhtbHkpTw4JVZBnALc05i
'' SIG '' oj1Nmp3PrqpYiZOb98VU6UZ5Qd1jMMMX2Kq3/wDE9AqH
'' SIG '' 9ZWTUuuBFieg6W2nBQO5h/YuOh6MTXGEwqHhciWfNUDQ9Og=
'' SIG '' End signature block
