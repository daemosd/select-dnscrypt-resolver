# DNSCrypt Resolver Selector
This is a fun little script I wrote which when invoked sets up a DNScrypt channel from your machine to a DNSCrypt resolver. If you don't specify a resolver, one is randomly chosen for you. The resolver listing is taken from the *dnscrypt-resolvers.csv* file as it is specified in the master dnscrypt-proxy repo at https://github.com/jedisct1/dnscrypt-proxy. 

There certainly exist much better and more straightforward Windows based implementations of DNSCrypt (DNSCrypt-winclient: https://github.com/Noxwizard/dnscrypt-winclient and Simple DNSCrypt https://simplednscrypt.org/ for example), but for those who prefer interacting with DNSCrypt using the powershell prompt, you may get some use out of this!

### Requirements
- Windows Powershell 3.0+ - certain script variables such as $PSScriptRoot are only available in Powershell versions >=3.0. Please reference the following resource below in order to determine your version and how to update to a more recent version of Powershell:
    - http://mikefrobbins.com/2015/01/08/how-to-check-the-powershell-version-and-install-a-new-version/
	
- The dnscrypt-proxy.exe file. You can get the latest version of this program at https://download.dnscrypt.org/dnscrypt-proxy/LATEST-win32-full.zip

- The dnscrypt-resolvers.csv file. You can get this file either by cloning/pulling the latest master branch from the dnscrypt-proxy gitrepo itself (that link again is https://github.com/jedisct1/dnscrypt-proxy) or by downloading the same zip file where the *dnscrypt-proxy.exe* file is stored

- Administrator privileges in the event local user privileges hold you back from launching certain aspects of this script (I'm assuming most users will use this script in a SOHO-like environment where they can perform tasks with administrative privileges).

### Usage
The motivating factor behind this script was to startup the DNSCrypt service and connection as a Windows startup task. Also to make the selection of the server that I connect to more dynamic (it would be somewhat boring and too reliant to always pick the same server, though I still make that option available in my script).

You could choose to use the Windows Startup Folder, but I went with Windows Task Scheduler and created a new startup task and pass in my powershell script as the program to run. If you wish to keep UAC from becoming a nuisance at startup, you'll want to make sure that your Task Scheduler job is running with the highest account privileges available for your system.

### TODOs
Add support for plugins and for sharing the proxy with the local network.

Fix all commented sections of code marked with TODOs in order to better optimize the runtime and/or overall presentation of this script.