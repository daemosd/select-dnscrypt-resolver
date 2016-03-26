<#

  .SYNOPSIS
  Creates a new DNSCrypt Proxy Service and connection using either a randomly chosen or explicitly specified DNSCrypt resolver name. 
  
  .DESCRIPTION
  The start-dnscrypt-proxy-resolver script uses the Windows DNSCrypt Proxy Executable developed by the DNSCrypt team in order to dynamically create
  a new DNSCrypt windows service that establishes proxied DNSCrypt connections to a given DNSCrypt Resolver. This is the primary intent of the script, but you can also run it
  to setup a local DNSCrypt listener in the event your account does not possess administrative privileges to create new Windows services. 
  
  Every time the script is executed, the service is uninstalled (whether it already exists or not) and the script then installs the service again using a given resolver that the user provides. 
  If no resolver is specified, a random resolver will be chosen from the master dnscrypt-resolvers.csv file that the DNSCrypt developers maintain. 
  The script logic does its best to adhere to the usage guidelines of the windows client at https://github.com/jedisct1/dnscrypt-proxy/blob/master/README-WINDOWS.markdown

  With no arguments specified, the script will simply pick a random DNSCrypt resolver for the client to use and it will check the current directory where 
  the script is being run from for the necessary dnscrypt_proxy.exe and dnscrypt-resolvers.csv files. See the .PARAMETER section for parameters that can 
  modify these default settings. All stdout/stderr logging of dnscrypt-proxy and script activity is made to the powershell console and it can be redirect to a specified logging file
  using the necessary logging switches and parameters.
  
  Once the script has completed successfully, make sure that you modify your necessary adapter settings so that the DNS Servers are configured to localhost 
  IP addresses and you should be good to go. The logging to dnscrypt-proxy.exe information, warning, notice and error messages to stdout/stderr by default should make this clear.
  
  Lastly, ensure that you have a version of Powershell installed >=3.0. Certain syntax in the script exists only in more recent versions of Powershell.
  
  .PARAMETER proxy_exe
  Path to the dnscrypt_proxy.exe file. The default is to check the directory where the script is located and raise an error if the executable cannot be found.
  
  Errors will be raised later in the script if the file provided is not that of the dnscrypt-proxy.exe file
  
  .PARAMETER resolvers_csv_file
  Path to the dnscrypt-resolvers.csv file. The default is to check the directory where the script is located and raise an error if the file cannot be found.
  
  Errors will be raised later in the script if the file provided is not that of the dnscrypt-proxy.exe file
  
  .PARAMETER resolver_name
  Specify a specific resolver to use for DNSCrypt communication. A null value defaults to randomly selcting a name from the local dnscrypt-resolvers CSV file
  
  The resolver name provided must exist in the dnscrypt-resolvers.csv file that is read in by the script. This particular check will be handled by the executable so long as it knows where to find the resolvers csv file.

  .PARAMETER LogToFile
  Switch to enable logging of script generated statements to a specified log file. Disabled by default, so messages only go to console stdout/stderr
  
  .PARAMETER logfile
  Path to the file where script log messages should be written. Default is a file named "script_out.txt" located in the same directory as the script itself.
  
  .PARAMETER runAsService
  Switch to control whether DNSCrypt Proxy should be started as a Windows Service or a local running process. The former requires the user first have administrativ privileges, the latter any user can perform.
  
  .INPUTS 
  None. This script does not accepts any piped objects
  
  .OUTPUTS
  System.String. Script logging messages are printed to the console when run, with logging support added when the necessary switch is specified.
  
  .EXAMPLE 
  (Any User) C:\PS> .\select-dnscrypt-resolver.ps1
  <...trim log lines...>
  [SCRIPT INFO] Starting local DNS Proxy listener as a regular user
  [SCRIPT INFO] Killed any previously running dnscrypt-proxy task(s)
  [SCRIPT INFO] Successfully setup local DNSCrypt proxy listener
  [SCRIPT INFO] Now connected to DNSCrypt resolver: cs-ch
  
  Note that dnscrypt-proxy.exe console messages will appear in new CMD window that pops up. 
  
  .EXAMPLE
  (Any User) C:\PS> .\select-dnscrypt-resolver.ps1 -resolver_name "okturtles"
  <...trim log lines...>
  [SCRIPT INFO] Starting local DNS Proxy listener as a regular user
  [SCRIPT INFO] Killed any previously running dnscrypt-proxy task(s)
  [SCRIPT INFO] Successfully setup local DNSCrypt proxy listener
  [SCRIPT INFO] Now connected to DNSCrypt resolver: okturtles
  
  Note the output is identical to Example 1 but the resolver you specify appears in the last script log line
  
  .EXAMPLE
  (Administrator) C:\PS> .\select-dnscrypt-resolver.ps1 -runAsService
  <...trim log lines...>
  [SCRIPT INFO] Setting up new DNS Proxy Service as an Administrator
  [INFO] The dnscrypt-proxy service has been removed from this system
  [SCRIPT INFO] Uninstalled previously existing dnscrypt-proxy service
  [INFO] The dnscrypt-proxy service has been installed and started
  [INFO] The registry key used for this service is SYSTEM\CurrentControlSet\Services\dnscrypt-proxy\Parameters
  [INFO] Now, change your resolver settings to 127.0.0.1:53
  [SCRIPT INFO] Successfully installed new instance of dnscrypt proxy service.
  [SCRIPT INFO] Now connected to DNSCrypt resolver: fvz-rec-nz-akl-01-ipv6
  
  No new windows will pop up in response to this command, everything takes place behind the scenese as a global dnscrypt service is created for all users on the system.
  
  Note that if you run the above command as a non Administrator you will receive an Insufficient Privileges type exception message.
  
  .EXAMPLE
  (Any User) C:\PS> .\select-dnscrypt-resolver.ps1 -LogToFile -logfile "C:\MyDirectory\temp\temp.txt"
  <...same output as example 1...>
  
  This is just like the first example but this will create a log file in the specified -logfile parameter directory (overrides the default if specified) which contains the same output as what appears on the console.
  
  Make sure that you have permissions to write to the directory you specified. Otherwise, you may receive a "Cannot Validate argument" exception during the ValidateScript checks performed on the parameter early on in script initialization.
  
  
  .LINK
  #https://github.com/daemosd/select-dnscrypt-resolver
#>

# Set up necessary script arguments (default value invoked if argument flag is not provided at runtime)
[CmdletBinding()]
Param(
	[parameter()]
	[ValidateScript({Test-Path $_ -include *dnscrypt-proxy.exe})]
	[string]
	$proxy_exe = "$PSScriptRoot\dnscrypt-proxy.exe"
,
	[parameter()]
	[ValidateScript({Test-Path $_ -include *dnscrypt-resolvers.csv})]
	[string]
	$resolvers_csv_file = "$PSScriptRoot\dnscrypt-resolvers.csv"
,
	[parameter()]
	[AllowNull()]
	[string]
	$resolver_name
,
	[switch]
	$LogToFile
,
	[parameter()]
	[ValidateScript({Test-Path $_ -PathType Leaf})]
	[string]
	$logfile = "$PSScriptRoot\script_logger.txt"
,
	[switch]
	$runAsService
#	[switch]
#	$setLocalhostDNSNetAdapters
#,
#	[parameter()]
#	[AllowNull()]
#	[string[]]
#	$interface_names
)

# If Logging swtich set, confirm that logging file exist on the file system
if ($LogToFile) {
	if (-not (Test-Path $logfile)){
		New-Item -Force -ItemType File -Path $logfile | Out-Null;
	}
}

# Function to handle output redirection to both console and log file (if logging switch set)
# TODO: Input parameter isn't picking up string being passed in for some reason, investigate
function LoggingHandler([string]$logfile, [string]$input) {	
	Process {
		Write-Host $logfile;
		if ($LogToFile) {
			out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $input" -append;		
		}
		Write-Host $input;
	}
}
#Logging $stdout_log "[SCRIPT INFO] DNSCrypt Proxy EXE located at $proxy_exe";

# Print a log separting line at the end of each script execution (whether success or failure)
function LogSeparator(){
    if ($LogToFile) { 
		out-file -filepath $logfile -inputobject "--------------------------------------------------" -append; 
	}
}
"[SCRIPT INFO] DNSCrypt Proxy EXE located at $proxy_exe" | 
    %{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_ };
"[SCRIPT INFO] DNSCrypt Resolvers CSV file located at $resolvers_csv_file" | 
	%{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_ };
	
# If runAsService switch set, check that script is being run with administrative privileges
# Backwards compatible implementation - Powershell 4.0 allows for #Requires -RunAsAdministrator check
if ($runAsService){
	function Test-Administrator {
		$user = [Security.Principal.WindowsIdentity]::GetCurrent();
		(New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
	} 
	if (-Not (Test-Administrator)) {
		"[SCRIPT ERROR] Service creation requested but the script is not being run with administrative privileges!" |
			%{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-ERROR $_ };
		"[SCRIPT ERROR] Exiting with ExitCode 11" |
			%{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_ };
		LogSeparator;
		exit 11;
	} else {
	    "[SCRIPT INFO] Setting up new DNS Proxy Service as an Administrator" |
		    %{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_ };
	}
} else {
    "[SCRIPT INFO] Starting local DNS Proxy listener as a regular user" |
	    %{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_ };
}

# If runAsService switch set, then first uninstall any pre-existing dnscrypt-proxy Windows service
# Command returns same output regardless if the service already exists or not
# Here, no News is good news
if ($runAsService) {
	$output = Start-Process -FilePath $proxy_exe -ArgumentList "--uninstall" -NoNewWindow -Wait;
	if ($output.ExitCode) {
		"[SCRIPT ERROR] Uninstall of Proxy Service Failed!" |
			%{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-ERROR $_ };
		"[SCRIPT ERROR] Exiting with ExitCode 12" |
			%{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_ };
		LogSeparator;
		exit 12;
	} else {
	    "[SCRIPT INFO] Uninstalled previously existing dnscrypt-proxy service" | 
			%{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_ };
	}
} else {
    # Kill any running processes of dnscrypt_proxy if they are present (continue on otherwise)
	try {
		Stop-Process -processname dnscrypt-proxy -ErrorAction Stop;
	} 
	catch {
	    # Silently continue over the error where it states the dnscrypt-proxy cannot be found in list of running processes 
		# as this does not impact future script execution.
		# Catch and handle all other errors.
		if (-not (Select-String -inputobject $_.Exception.Message -pattern 'Cannot find a process with the name "dnscrypt-proxy"')) {
			"[SCRIPT ERROR] Could not terminate dnscrypt-proxy instance. Most likely the process was initiated by someone with administrative privileges. Check with your Administrator" |
				%{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-ERROR $_ };
			"[SCRIPT ERROR] Exiting with ExitCode 13" |
				%{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_ };
			LogSeparator;
			exit 13;
		}
	}
	"[SCRIPT INFO] Killed any previously running dnscrypt-proxy task(s)" |
	    %{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_ };
}

# If the user hasn't specified a resolver name, then compile a list of resolver names and randomly select one
if (-not ($resolver_name)) {
    # Account for any other errors involving CSV file
    try {
		$resolver_entry = Import-Csv $resolvers_csv_file | Get-Random;
		$resolver_name = $resolver_entry.Name;
    } catch {
	    "[SCRIPT ERROR] $_.Exception.Message" |
			%{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-ERROR $_ };
		"[SCRIPT ERROR] Exiting with ExitCode 14" |
			%{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_ };
		LogSeparator;
		exit 14;
	}
}

# If runAsService switch set, install the Proxy Service
# Again, no news is good news
if ($runAsService) {
	$output = Start-Process -FilePath $proxy_exe -ArgumentList "-L $resolvers_csv_file -R $resolver_name --install" -NoNewWindow -PassThru -Wait;
	if ($output.ExitCode) {
		"[SCRIPT ERROR] Install of Proxy Service and Resolver Communication has failed." |
			%{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-ERROR $_ };
		"[SCRIPT ERROR] Exiting with ExitCode 15" |
			%{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_ };
		LogSeparator;
		exit 15;
	} else {
	    "[SCRIPT INFO] Successfully installed new instance of dnscrypt proxy service." |
		    %{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_ };
	}
} else {
    # Similar to above, the only difference that we drop the --install argument and display a new window where we don't wait 
	# Given that the dnscrypt-proxy by default runs in the foreground and blocks in order to listen, this keeps it from interfering with current PS session.
	# TODO: See if this can be made better rather than waiting 3 seconds in order to determine if process is still running or not
	$output = Start-Process -FilePath $proxy_exe -ArgumentList "-L $resolvers_csv_file -R $resolver_name" -PassThru;
	Start-Sleep -s 3;
	# If the process is still present, it started fine. Otherwise, it failed to startup properly - return an error
	try {
	    Get-Process -processname dnscrypt-proxy -ErrorAction Stop | Out-Null;
		"[SCRIPT INFO] Successfully setup local DNSCrypt proxy listener" |
		    %{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_ };
	} 
	catch [System.Management.Automation.ActionPreferenceStopException] {
	    "[SCRIPT ERROR] Process failed to start. Check your script inputs and also check that an existing dnscrypt proxy channel is not currently listening" |
		    %{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-ERROR $_ };
		"[SCRIPT ERROR] Exiting with ExitCode 16" |
			%{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_ };
		LogSeparator;
		exit 16;
	} 
}

"[SCRIPT INFO] Now connected to DNSCrypt resolver: $resolver_name" |
	%{if ($LogToFile){ out-file -filepath $logfile -inputobject "$(Get-Date -Format o): $_" -append;} Write-Host $_};
LogSeparator;
#DONE