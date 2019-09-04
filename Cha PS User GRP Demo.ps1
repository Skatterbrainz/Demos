Function Hashing{

Get-FileHash C:\Windows\write.exe

Get-FileHash C:\Windows\*

Get-ChildItem C:\Windows | Get-FileHash 

# 
Get-Process | Get-Member

Get-process | Select-Object * -First 1

Get-process | Select name -ExpandProperty modules -First 1 

$p = Get-Process
$p.path
(get-process).path


$processes = Get-Process
foreach ($proc in $processes){
    try{
        Get-FileHash $proc.path -Algorithm SHA1 -ErrorAction stop
    }
    catch{
        #error handling... log contains names of processes where there was no path listed or we lack the rights
        $proc.name | out-file c:\proc_hash_error.log -Append
    }
}


$procHash = @()
$processes = get-process
foreach ($proc in $processes){
    try{
        $procHash += Get-FileHash $proc.path -Algorithm SHA1 -ErrorAction stop
    }
    catch{
         #error handling... log contains names of processes where there was no path listed or we lack the rights
         $proc.name | out-file c:\proc_hash_error2.log -Append
    }
}
$procHash


# Finding duplicate hashes
Copy-Item C:\Windows\write.exe C:\Windows\w.exe

$hashList = Get-ChildItem c:\windows | Get-FileHash -Algorithm md5
$hashUnique = $hashList.hash | select-object -Unique

$hashDiff =(Compare-object –referenceobject $hashUnique –differenceobject $hashList.hash).inputobject

foreach($hash in $hashList){
    foreach($hashD in $hashDiff){
        if($hash.hash -eq $hashD){
            $hash
        }
    }
}

# Cleanup
Remove-Item C:\Windows\w.exe


} # Hashing


Function Data_Storage{

# Registry string store
[System.Text.Encoding] | get-member -Static
[System.Text.Encoding]::Unicode | get-member

[System.Convert] | get-member -Static

$Data2Encode = ‘PowerShell is Great!’
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Data2Encode)
$EncodedText =[System.Convert]::ToBase64String($Bytes)
$EncodedText
New-ItemProperty HKLM:\software -Name "updater32" -Value $EncodedText -PropertyType multistring

Get-ItemProperty HKLM:\SOFTWARE

# Registry string retrieval
$Data2Decode = (Get-ItemProperty HKLM:\software).updater32
$bytes = [System.Convert]::FromBase64String($Data2Decode)
$DecodedText = [System.Text.Encoding]::Unicode.GetString($bytes)
$DecodedText


Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell"
Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell" | Get-Member
(Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell").links.href
((Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell").links.href).count
((Invoke-WebRequest -uri "https://en.wikiversity.org/wiki/PowerShell").images.src).count
(Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell").images.src


# Registry Stager Store
$command = 'Start-BitsTransfer -Source "https://en.wikiversity.org/static/images/wikimedia-button.png" -Destination "$env:USERPROFILE\desktop\button.jpg"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
$EncodedCommand
New-ItemProperty HKLM:\software -Name "updater15" -Value $encodedCommand -PropertyType multistring


# Registry Stager Retrieval
$cmd = Get-ItemPropertyValue HKLM:\SOFTWARE -Name "updater15"
powershell.exe -noprofile -encodedCommand $cmd


# Registry binary store
$bytes = get-content C:\WINDOWS\system32\calc.exe -Encoding Byte
$EncodedText =[System.Convert]::ToBase64String($Bytes)
$EncodedText
New-ItemProperty HKLM:\software -Name "updater64" -Value $EncodedText -PropertyType multistring


# Registry binary retrieval
$Data2Decode = (Get-ItemProperty HKLM:\software).updater64
$bytes = [System.Convert]::FromBase64String($Data2Decode)
$bytes | Set-Content ("$Env:USERPROFILE\desktop\calc.exe") -Encoding Byte
& ("$Env:USERPROFILE\desktop\calc.exe")


# Cleanup
Remove-ItemProperty HKLM:\SOFTWARE -Name "updater32"
Remove-ItemProperty HKLM:\SOFTWARE -Name "updater15"
Remove-ItemProperty HKLM:\SOFTWARE -Name "updater64"
Remove-Item "$env:USERPROFILE\desktop\button.jpg"
Remove-item "$env:USERPROFILE\desktop\calc.exe"


} # Data_Storage


Function Eventlogs{

# Get-Eventlog
Get-EventLog -LogName Security -InstanceId 4688
Get-EventLog -LogName Security -InstanceId 4688 | Select-Object *-first 1

#
Get-EventLog -LogName Security -InstanceId 4688 | select * -first 1 -ExpandProperty replacementstrings

#
Get-EventLog -LogName Security -InstanceId 4688 | select Timegenerated, @{Label='Process';expression={$_.ReplacementStrings[5]}}

# 
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} 
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | select * -First 1

# 
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} |select properties -expandproperty properties -first 1 | Format-List 

# 
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} |select timecreated, @{Label="Process";Expression={$_.properties.value[5]}} | export-csv c:\test.csv


# Create a custom log source
New-EventLog -logname application -Source "Processes"


# Create a custom log source that already exists
New-EventLog -LogName application -Source "MsiInstaller"


# Write to the eventlog
Write-EventLog -LogName application -Source "Processes" -entrytype Information -eventid 1337 -Message "Feed me data!!"


while($true){
    $date = get-date 
    $date
    Start-Sleep 10
    $procs = get-process -IncludeUserName

    foreach($proc in $procs){
        if (($date) -lt $proc.StartTime){
            [string]$procStart = $proc.StartTime
            $procName = $proc.name
            $procPath = $proc.path
            $procID = ($proc.id).ToString()
            $procSId = ($proc.SessionId).ToString()
            $procUser =$proc.UserName
            Write-EventLog -LogName application -Source "Processes" -entrytype Information -eventid 1337 -Message "StartTime: $procStart`nName: $procName`nPath: $procPath`nID: $procid`nSessionID: $procSId`nUserName: $procUser"
        }
    }
}


# Create a new eventlog
New-EventLog -LogName "workshop" -Source "Star-lord"
Write-EventLog -LogName "workshop" -Source "Star-lord" -entrytype Information -eventid 7331 -Message "Peter Quill in the flesh!"


# Cleanup
Remove-EventLog -Source "Processes"
Remove-EventLog -LogName "workshop"


} # Eventlogs


Function Port_Scanning{

#
Get-NetTCPConnection | Get-Member

Get-NetTCPConnection

$443 = New-Object system.net.sockets.tcplistener 443
$23 = [system.net.sockets.tcplistener]::Create(23)

$443.Start()
$23.start()

Get-NetTCPConnection -LocalPort 443, 23

# 
Test-NetConnection | Get-Member

# 
Test-NetConnection -ComputerName 10.1.1.1 -Port 443

# 
Test-NetConnection -ComputerName 10.1.1.1 -Port 800

# Adding suppression
Test-NetConnection -ComputerName 10.1.1.1 -Port 800 -WarningAction SilentlyContinue

# Fields we care about
Test-NetConnection -ComputerName 10.1.1.1 -Port 80 | select-object RemoteAddress, RemotePort, TcpTestSucceeded, PingSucceeded

# More than one port
$ports = 22,23,53,80,443
foreach($port in $ports){
    Test-NetConnection -ComputerName 10.1.1.1 -Port $port | select-object RemoteAddress, RemotePort, TcpTestSucceeded, PingSucceeded
}

# With suppression
$ports = 22,23,53,80,443
foreach($port in $ports){
    Test-NetConnection -ComputerName 10.1.1.1 -Port $port -WarningAction SilentlyContinue| select-object RemoteAddress, RemotePort, TcpTestSucceeded, PingSucceeded
}


# Net.Sockets.TCPClient
$ports = 22, 23, 80, 443
$IP = "10.1.1.1"
$scan = foreach($port in $ports){
    try{
        $portStatus = new-object Net.Sockets.TcpClient($IP, $port)
        [pscustomobject]@{
            RemoteAddress = $IP
            RemotePort = $port
            TcpTestSucceeded =  $portStatus.connected
        }
        $portStatus.Close()
    }
    catch{
        [pscustomobject]@{
            RemoteAddress = $IP
            RemotePort = $port
            TcpTestSucceeded = 'false'
        }
    }
}
$scan

                                                                                                                                                     
} # Port_Scanning


Function Profiles{

# Functions

Get-ChildItem function:\wp

function wp{
    & "C:\Program Files (x86)\windows nt\accessories\wordpad.exe"
}

Get-ChildItem function:\wp

Get-ChildItem function:\wp | Select-Object -ExpandProperty scriptblock


# Profiles
$profile
$profile | format-list * -force


# Check Profiles
test-path $profile


# Create profile
if(-not(test-path $profile)){new-item -ItemType file -Path $profile}

#
Write-Output "function notepad{c:\windows\notepad.exe; c:\windows\system32\calc.exe}" | out-file $profile

# Cleanup
Write-Output " " | Out-File $profile


} # Profiles