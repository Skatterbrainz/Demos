# Enable process creation commandline logging
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit -name ProcessCreationIncludeCmdLine_Enabled -Value 0


function Primer{

Get-Help

Get-Help address

Get-Help Get-NetIPAddress

Get-Help Get-NetIPAddress -Examples

Get-Help Get-NetIPAddress -ShowWindow

Get-Help Get-NetIPAddress -Full

Get-Command

Get-PSDrive

Get-ChildItem -Name C:\

Get-ChildItem -Name C:\Windows\System32\*.exe

Get-ChildItem -Name HKLM:\

Get-ChildItem -Name 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 

Write-Output "PowerShell" | Out-File "$env:USERPROFILE\desktop\myfile.txt"

Get-Content -Path "$env:USERPROFILE\desktop\myfile.txt"

"powershell, " * 5

"PowerShell" -eq "powershell"

1 -eq 1 -and 2 -eq 3
 
1 -eq 1 -or 2 -eq 3

1..10

$num++
$num

$myNum = 123

$myStr = "abc"
 
Get-Process | Get-Member

$process = Get-Process

$process.Name
(get-process).Name

Start-Process -FilePath "regedit"
(get-process -Name "regedit").kill()

#
If ((get-date).dayofweek -eq "Monday" ){
    Write-Output "Today is " + (get-date)
}
Else{
    Write-Output "Today is not Monday"
}


# 
$now = Get-Date
if ($now.DayOfWeek -eq 'sunday' -AND $now.hour -gt 12){
    Write-Output "The first day of the week is almost over!"
}


# 
$os = (Get-CimInstance -Namespace root/cimv2 -ClassName win32_operatingsystem).caption

if ($os -match "7"){
    Write-Output "Likely Windows 7"
}
elseif($os -match "8"){
    Write-Output "Likely Windows 8"
}
elseif($os -match "10"){
    Write-Output "Likely Windows 10"
}
else{
    Write-Output "Unknown operating system"
}


#
$services = get-service
 
ForEach ($item in $services){
	$item.name + " : " + $item.status
}
Write-Output "`nThe last service is $($item.name)" 
    

#
$question = "Are we there yet?"
$answer = "Noooooo!"
for ($i = 3; $i -gt 0; $i--){
    $question
    sleep 2
}

Write-Output "`n$answer"



# 
$food = 'Beans', 'Greens', 'Potatoes', 'Lamb', 'Rams', 'Hogs', 'Dogs'

for ($i = 5; $i -gt 0; $i--)
{
    foreach($item in $food){
        Write-Output "I got $item "
    }
}

Write-Output "`nYou name it!"


#
while ($true){
    test-connection 127.0.0.1
}


# Each iteration will multiply the number of rabbits by two
$rabbits = 2
Do{
    Write-output "We now have $rabbits rabbits!"
    $rabbits *= 2
}
While ($rabbits -lt 10000)


# 
$i = 0
while($i -lt 999){
    $i++
    $i
}
Write-Host "`nCount complete - We have counted up to $i"


} # Primer


Function Hashing{

Get-FileHash C:\Windows\write.exe

Get-ChildItem C:\Windows | Get-FileHash 

# 
Get-Process | Get-Member

Get-process | Select-Object * -First 1

Get-process | Select -ExpandProperty modules -First 1 

Get-process | Select name -ExpandProperty modules -First 1 | Format-List

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


# Finding duplicate hashes
Copy-Item C:\Windows\write.exe C:\Windows\w.exe

$baseHashes = Get-ChildItem c:\windows | Get-FileHash -Algorithm md5
$uniqueBaseHashes = $baseHashes.hash | select-object -Unique

$diffHashes =(Compare-object –referenceobject $uniqueBaseHashes –differenceobject $baseHashes.hash).inputobject

foreach($hash in $baseHashes){
    foreach($diff in $diffHashes){
        if($hash.hash -eq $diff){
            $hash
        }
    }
}

# Cleanup
Remove-Item C:\Windows\w.exe
Remove-Item C:\proc_hash_error.log


} # Hashing


Function Data_Storage{

#
Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell"
Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell" | Get-Member
(Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell").links.href
((Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell").links.href).count
((Invoke-WebRequest -uri "https://en.wikiversity.org/wiki/PowerShell").images.src).count
(Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell").images.src

Invoke-WebRequest -Uri "https://upload.wikimedia.org/wikipedia/commons/thumb/2/2f/PowerShell_5.0_icon.png/64px-PowerShell_5.0_icon.png" -OutFile "$env:USERPROFILE\desktop\ps.jpg"
Invoke-Item -path "$env:USERPROFILE\desktop\ps.jpg"

# Registry string store
[System.Text.Encoding] | get-member -Static
[System.Text.Encoding]::Unicode | get-member

[System.Convert] | get-member -Static

$Data2Encode = ‘PowerShell is Great!’
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Data2Encode)
$EncodedText =[System.Convert]::ToBase64String($Bytes)
$EncodedText
New-ItemProperty -path HKLM:\Software -Name "updater32" -Value $EncodedText -PropertyType multistring

Get-ItemProperty -path HKLM:\Software

# Registry string retrieval
$Data2Decode = (Get-ItemProperty HKLM:\software).updater32
$bytes = [System.Convert]::FromBase64String($Data2Decode)
$DecodedText = [System.Text.Encoding]::Unicode.GetString($bytes)
$DecodedText

# Registry Stager Store
$command = 'Start-BitsTransfer -Source "http://www.funnycatpix.com/_pics/Playing_A_Game.jpg" -Destination "$env:USERPROFILE\desktop\cat.jpg"' 
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
$EncodedCommand
New-ItemProperty -path HKLM:\software -Name "updater15" -Value $encodedCommand -PropertyType multistring

# Registry Stager Retrieval
$cmd = Get-ItemPropertyValue HKLM:\SOFTWARE -Name "updater15"
powershell.exe -noprofile -encodedCommand $cmd
Invoke-Item -Path $env:USERPROFILE\desktop\cat.jpg

# Registry binary store
$bytes = get-content C:\WINDOWS\system32\calc.exe -Encoding Byte
$EncodedText =[System.Convert]::ToBase64String($Bytes)
$EncodedText
New-ItemProperty -path HKLM:\software -Name "updater64" -Value $EncodedText -PropertyType multistring


# Registry binary retrieval
$Data2Decode = (Get-ItemProperty HKLM:\software).updater64
$bytes = [System.Convert]::FromBase64String($Data2Decode)
$bytes | Set-Content ("$Env:USERPROFILE\desktop\calc.exe") -Encoding Byte
& ("$Env:USERPROFILE\desktop\calc.exe")


# Cleanup
Remove-ItemProperty HKLM:\SOFTWARE -Name "updater32"
Remove-ItemProperty HKLM:\SOFTWARE -Name "updater15"
Remove-ItemProperty HKLM:\SOFTWARE -Name "updater64"
Remove-Item "$env:USERPROFILE\desktop\ps.jpg"
Remove-item "$env:USERPROFILE\desktop\calc.exe"
Remove-item "$env:USERPROFILE\desktop\cat.jpg"


} # Data_Storage


function WMI_Classes{

Get-WmiObject -Namespace root/cimv2 -List | sort-object
Get-CimClass -Namespace root/cimv2 | Sort-Object

Get-WmiObject –Namespace root –List -Recurse | Measure-Object

Get-CimInstance -Namespace root/cimv2 -Classname win32_ntlogevent -filter "logfile='security'"
Get-CimInstance -Namespace root/cimv2 -Classname win32_startupcommand
Get-CimInstance -Namespace root/cimv2 -Classname win32_quickfixengineering
(Get-CimInstance -Namespace root/cimv2 -ClassName win32_operatingsystem).OSArchitecture


$StaticClass = New-Object Management.ManagementClass('root\cimv2', $null, $null)
$StaticClass.Name = 'Win33_Secret'
$StaticClass.Put()

$StaticClass.Properties.Add('MyProperty' , "This is just a test to see if data can be stored")
$StaticClass.Put()

$StaticClass | Select-Object -ExpandProperty properties
($StaticClass | Select-Object -ExpandProperty properties).value

$Data2Encode = "get-date | out-file $env:USERPROFILE\desktop\wmi_date.txt"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Data2Encode)
$EncodedText =[System.Convert]::ToBase64String($Bytes)
$EncodedText

$StaticClass.Properties.Add('MyCode' , "$EncodedText")
$StaticClass.Put()

$StaticClass | Select-Object -ExpandProperty properties
($StaticClass | Select-Object -ExpandProperty properties).value

powershell -encodedcommand (($StaticClass | Select-Object -ExpandProperty properties | Where-Object{$_.name -eq "mycode"}).value)
powershell -encodedcommand (($StaticClass).Properties['mycode'].value)

(Get-CimClass -Namespace root/cimv2 -ClassName win33_secret).CimClassProperties['mycode'].value
(Get-WmiObject -Namespace root/cimv2 -ClassName win33_secret -list).properties['myproperty'].value
(Get-CimClass -Namespace root/cimv2 -ClassName win33_secret | Select-Object -ExpandProperty cimclassproperties | Where-Object{$_.name -eq "mycode"}).value
(Get-WmiObject -Namespace root/cimv2 -ClassName win33_secret -list | Select-Object -ExpandProperty properties | Where-Object{$_.name -eq "mycode"}).value

powershell -encodedcommand ((Get-CimClass -Namespace root/cimv2 -ClassName win33_secret).CimClassProperties['mycode'].value)
powershell -encodedcommand ((Get-WmiObject -Namespace root/cimv2 -ClassName win33_secret -list | Select-Object -ExpandProperty properties | Where-Object{$_.name -eq "mycode"}).value)

$StaticClass.Delete()
$StaticClass.Dispose()

# Verify the Class is gone
Remove-WmiObject -Namespace root/cimv2 -class win33_secret

# Cleanup
Remove-Item "$env:USERPROFILE\desktop\wmi_date.txt"


} # WMI_Classes


function WMI_Subscription{

Register-WmiEvent -Query "Select * from __InstanceoperationEvent within 60 where targetinstance ISA 'win32_process' AND targetinstance.name='lsass.exe'" -SourceIdentifier "test" -Action{$nc = "nc -nvl 443";}

# Temp WMI Register... dies when the process terminates
Register-CimIndicationEvent -Query "Select * from __InstanceoperationEvent within 20 where targetinstance ISA 'win32_process' AND targetinstance.name='lsass.exe'" -SourceIdentifier "abc" -Action{Write-Output "$(get-date) - Temp WMI Register Executed Successfully" | Out-File $env:USERPROFILE\Desktop\logger.txt -Append}

# Temp WMI register... nc example
Register-CimIndicationEvent -Query "Select * from __InstanceoperationEvent within 60 where targetinstance ISA 'win32_process' AND targetinstance.name='lsass.exe'" -SourceIdentifier "test" -Action{$conn = Get-NetTCPConnection | Where-Object{$_.LocalPort -eq 4444 -and $_.State -eq "established"}; if($conn -ne $null){$nc = "nc -nvl 4444"}}


Get-EventSubscriber
Get-Job

# Cleanup
Unregister-Event -SourceIdentifier test
get-job -Id 27 | Stop-Job


} # WMI_Subscription


Function Eventlogs{

# Get-Eventlog
Get-EventLog -LogName Security -InstanceId 4688
Get-EventLog -LogName Security -InstanceId 4688 | Select-Object * -first 1

#
Get-EventLog -LogName Security -InstanceId 4688 | Select-Object * -first 1 -ExpandProperty replacementstrings

#
Get-EventLog -LogName Security -InstanceId 4688 | Select-Object Timegenerated, @{Label='Process';expression={$_.ReplacementStrings[5]}} -first 1
 
# 
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} 
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | Select-Object * -First 1

# 
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | Select-Object properties -expandproperty properties -first 1 | Format-List 

# 
$logs = Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | Select-Object * -First 1 
@($logs.Properties[0..($logs.Properties.count)])

#
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | Select-Object timecreated, @{Label="Process";Expression={$_.properties.value[5]}}

#
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | Select-Object timecreated, @{Label="Process";Expression={$_.properties.value[5]}}

# 
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | Select-Object timecreated, @{Label="Account";Expression={$_.properties.value[1]}}, @{Label="Commandline";Expression={$_.properties.value[8]}}, @{Label="ParentProcess";Expression={$_.properties.value[13]}} -first 1 | fl #| export-csv c:\test.csv


# Create a custom log source
New-EventLog -logname application -Source "Processes"


# Create a custom log source that already exists
New-EventLog -LogName application -Source "MsiInstaller"


# Write to the eventlog
Write-EventLog -LogName application -Source "Processes" -entrytype Information -eventid 1337 -Message "Feed me data!!"

[int]$num = 1
while($true){$num++;$num} 


foreach($myProc in (get-process).name){
    "workshop  " + $myProc
}


# Custom Process watcher eventlog entry
while($true){
    $date = get-date 
    $date
    Start-Sleep -Seconds 10
    $procs = get-process -IncludeUserName

    foreach($proc in $procs){
        if (($date) -lt $proc.StartTime){
            $process = $proc | Select-Object starttime, name, path, id, sessionid, username
            Write-EventLog -LogName application -Source "Processes" -entrytype Information -eventid 1337 -Message "$process"
        }
    }
}


# Custom Process watcher eventlog entry... second try
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
Get-EventLog -LogName "workshop"
New-EventLog -LogName "workshop" -Source "Star-lord"
Write-EventLog -LogName "workshop" -Source "Star-lord" -entrytype Information -eventid 7331 -Message "Peter Quill in the flesh!"


# Cleanup
Remove-EventLog -Source "Processes"
Remove-EventLog -LogName "workshop"


} # Eventlogs


function Timestomp{

$file = "$env:USERPROFILE\desktop\myfile.txt"

Get-Item $file | format-list *time*

(Get-Item -path $file).LastWriteTime = get-date

(Get-Item -path $file).LastWriteTime = (get-date).AddDays(-360)

(Get-Item -path $file).LastWriteTime = "8/8/2018 09:00:00 PM"

# Cleanup
Remove-Item "$env:USERPROFILE\desktop\myfile.txt"


} # Timestomp


Function WinRM{

#
winrm quickconfig 

enable-psremoting -Force

# 
Enter-PSSession 127.0.0.1
Get-WSManInstance -ConnectionURI ('http://localhost:5985/wsman') -ResourceURI shell -enumerate

Get-WSManInstance -ConnectionURI ('http://localhost:5985/wsman') -ResourceURI shell -enumerate | select ClientIP, ProcessID, ShellRunTime, ShellinActivity | Format-Table


} # WinRM


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
Test-NetConnection -ComputerName 127.0.0.1 -Port 443

# 
Test-NetConnection -ComputerName 127.0.0.1 -Port 800

# Adding suppression
Test-NetConnection -ComputerName 127.0.0.1 -Port 800 -WarningAction SilentlyContinue

# Fields we care about
Test-NetConnection -ComputerName 127.0.0.1 -Port 80 | select-object RemoteAddress, RemotePort, TcpTestSucceeded, PingSucceeded

# More than one port
$ports = 22,23,53,80,443
foreach($port in $ports){
    Test-NetConnection -ComputerName 127.0.0.1 -Port $port | select-object RemoteAddress, RemotePort, TcpTestSucceeded, PingSucceeded
}

# With suppression
$ports = 22,23,53,80,443
foreach($port in $ports){
    Test-NetConnection -ComputerName 127.0.0.1 -Port $port -WarningAction SilentlyContinue| select-object RemoteAddress, RemotePort, TcpTestSucceeded, PingSucceeded
}

# Single system and port
new-object Net.Sockets.TcpClient('8.8.8.8', '53')

# Net.Sockets.TCPClient
$ports = 22, 23, 80, 443
$IP = "127.0.0.1"
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
            TcpTestSucceeded = 'False'
        }
    }
}
$scan

                                                                                                                                                     
} # Port_Scanning


function Ping_Banner{

$sys = "127.0.0.1", "8.8.8.8", "192.99.167.156"

foreach($system in $sys){
    if(Test-Connection -count 1 -ComputerName $system -quiet){
        $system    
    }    
}


# Range
$ip = "192.168.0."
foreach($octet in 1..5){
    "$ip$octet : $(test-Connection -Count 1 -ComputerName ($ip + $octet) -Quiet)"    
}


# Range to object
$ip = "192.168.0."
$results = @{}
$results = foreach($octet in 1..5){
    $node = $ip + $octet
    $ttl = (test-Connection -Count 1 -ComputerName $node -ErrorAction SilentlyContinue).responsetimetolive
    if($ttl -ne $null){
        $online = "false"
    }
    else{
        $online = "true"
    }
    [pscustomobject]@{
        IP = $node
        Online = $online
    }
}
$results


# TTL
$ip = "192.168.0."
$results = @{}
$results = foreach($octet in 1..5){
    $node = $ip + $octet
    $ttl = (test-Connection -Count 1 -ComputerName $node -ErrorAction SilentlyContinue).responsetimetolive
    if($ttl -eq $null){
        $online = "false"
    }
    else{
        $online = "true"
    }
    [pscustomobject]@{
        IP = $node
        Online = $online
        TTL = $ttl
    }
}
$results


# Banner grab
$sys = "127.0.0.1", "8.8.8.8", "192.99.167.156"
$ports =  @(22, 80, 443)
$results=@{}

function banner ($sys, $port){   
    $socket = New-Object System.Net.Sockets.TCPClient
    $connected = ($socket.BeginConnect($sys, $Port, $Null, $Null)).AsyncWaitHandle.WaitOne(500)
    if ($connected -eq "$True"){
        $stream = $socket.getStream() 
        Start-Sleep -Milliseconds 1000
        $text = ""
        while ($stream.DataAvailable){ 
            $text += [char]$stream.ReadByte()
        }
        if ($text.Length -eq 0){ 
            $text = "$null"
        }
        $script:banner = "$text"
        $socket.Close()
    } 
    else{ }
}

$results = foreach($system in $sys){
        $ttl = (test-Connection -Count 1 -ComputerName $system -ErrorAction SilentlyContinue).responsetimetolive    
        if($ttl -eq $null){
            $online = "false"
        }
        else{
            $online = "true"
        }                                            
        foreach ($port in $ports) {     
            try {
                $TestPort = banner $system $port
            } catch { }           
            [pscustomobject]@{
                IP = $system
                Online = $online
                TTL = $ttl
                Port = $port
                Banner = $banner
            }
        }
    }
$results | format-table

# Cleanup
$443.Stop()
$23.stop()

Get-NetTCPConnection -LocalPort 443, 23


} # Ping_Banner


function SimpleHTTPServer{

Write-Output "get-date; write-output 'I Love PowerShell'" | Out-File $env:USERPROFILE\desktop\demo_script.ps1

Get-NetTCPConnection -LocalPort 4444

Start-Job -ScriptBlock{
$listener = New-Object Net.HttpListener
$listener.Prefixes.Add("http://+:4444/")
$listener.Start()

    While($listener.IsListening){
        $contextTask = $listener.GetContextAsync()
        While(-not $contextTask.AsyncWaitHandle.WaitOne(200)){ }
        $incoming = $contextTask.GetAwaiter().GetResult()
        $incomeResponse = $incoming.Response
        $incomeResponse.Headers.Add("Content-Type","text/plain")
        $Buf = [Text.Encoding]::UTF8.GetBytes((Get-Content (Join-Path $env:USERPROFILE\desktop ($incoming.Request).RawUrl)))
        $incomeResponse.ContentLength64 = $Buf.Length
        $incomeResponse.OutputStream.Write($Buf,0,$Buf.Length)
        $incomeResponse.Close()
    }
$listener.Stop()
}


} # SimpleHTTPServer


function Download_Files{

$web = New-Object System.Net.WebClient
$web.Headers.Add("user-agent","Windows-RSS-Platform/2.0 (MSIE 9.0; Windows NT 6.1)")
$url = "http://localhost:4444/demo_script.ps1"
$output = "$env:USERPROFILE\desktop\downloaded_script.ps1"
$web.DownloadFile($url, $output)

$web = New-Object System.Net.WebClient
$url = "http://localhost:4444/demo_script.ps1"
$cmd = $web.DownloadString($url) 
Invoke-Expression $cmd 


} # Download_File


function Execution_Policy{
Get-ExecutionPolicy
Set-ExecutionPolicy -ExecutionPolicy Restricted

& "$env:USERPROFILE\desktop\demo_script.ps1"

Get-Content $env:USERPROFILE\desktop\demo_script.ps1 | powershell

$data = Get-Content $env:USERPROFILE\desktop\demo_script.ps1 
Write-Output $data | powershell

powershell -executionpolicy bypass -file $env:USERPROFILE\desktop\demo_script.ps1

powershell -command "invoke-expression (new-object net.webclient).downloadstring('http://localhost:4444/demo_script.ps1')"


$Data2Encode = get-content "$env:USERPROFILE\desktop\demo_script.ps1"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Data2Encode)
$EncodedText =[System.Convert]::ToBase64String($Bytes)
$EncodedText

powershell -encodedcommand $EncodedText

Set-ExecutionPolicy -ExecutionPolicy Unrestricted


} # Execution_Policy


Function Profiles{

# Functions

Get-ChildItem function:\wp

function wp{
    & "C:\Program Files (x86)\windows nt\accessories\wordpad.exe"
}

Get-ChildItem function:\wp

Get-Content function:\wp
Get-ChildItem function:\wp | Select-Object -ExpandProperty scriptblock


# 
$profile
$profile |fl * -force


# 
test-path $profile


# Create profile
if(-not(test-path $profile)){new-item -ItemType file -Path $profile}

#
Write-Output "function notepad{c:\windows\notepad.exe; c:\windows\system32\calc.exe}" | out-file $profile

# Cleanup
Write-Output " " | Out-File $profile
get-job | Stop-Job
Remove-Item "$env:USERPROFILE\desktop\downloaded_script.ps1"
Remove-Item "$env:USERPROFILE\desktop\demo_script.ps1"

} # Profiles


Function DNS{

function Sinkhole-Hosts{
param([string[]]$domains)
    #Requires -RunAsAdministrator
    $file = "C:\Windows\System32\drivers\etc\hosts"
    $domains
    foreach($item in $domains){
        "0.0.0.0       $item" | out-file $file -append
    } 
}

function Restore-Hosts{
    $file = "C:\Windows\System32\drivers\etc\hosts"
    $hosts = get-content $file
    remove-item $file
    foreach($item in $hosts){
        if($item -like "`#*"){
            $item | out-file C:\Windows\System32\drivers\etc\hosts -Append      
        }
    }
}


}

