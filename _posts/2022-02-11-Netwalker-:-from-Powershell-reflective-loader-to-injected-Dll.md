---
layout: post
title:  "Netwalker: from Powershell reflective loader to injected dll"
date:   2022-02-11
categories: loaders netwalker
---

Hi! I have lately started delving into maliious powershell payloads and came across a really intriguing powershell loader for "[Netwalker ransomware][netwalker-ransomware]", performing [fileless attack][fileless-attacks]. Fileless techniques enable attackers to directly load and execute malicious binary in memory without actually storing it on disk by abusing available legitimate tools on victim machine. Such threats leave no trace of execution and are capable of evading any traditional security tools. This post thoroughly discusses how first stage powershell script filelessly loads and executes embedded payload through reflective Dll injection.

SHA-256 hash of the sample being analyzed:  [f4656a9af30e98ed2103194f798fa00fd1686618e3e62fba6b15c9959135b7be][link-to-download-ps1-loader]

-----------------------------------------------------------------------------------------------------------------------------------
Prior knowledge required:

- Basic Powershell understanding
- using .NET reflection to access Windows API in PowerShell
- Windows APIs for Process/Dll injection
    
-----------------------------------------------------------------------------------------------------------------------------------


This is around ~5 MBs of powershell script using three layers of encoding, encryption and obfuscation respectively to hide ransomware dll and supporting powershell commands for reflective Dll injection. The uppermost layer executes very long base64 encoded command (screenshot covers only a small portion of this command)

![image](/assets/images/psloader/layer1.png){:class="img-responsive"}

<h1>Processing Base64 encoded layer 1</h1>

In order to get decoded output from initial script, I shall run powershell script into my VM’s Powershell ISE but as the Invoke-Expression cmdlet will process base64-encoded payload and execute the ransomware therefore, I'll modify the script for debugging by replacing this comdlet with a variable to store result of base64 decoded command and dump output in a file as shown in the figure below

![image](/assets/images/psloader/layer1processing.png){:class="img-responsive"}


<h1>Processing Encrypted layer 2</h1>

base64 decoded second layer once again contains a very long bytearray in hex format which is processed in two steps

![image](/assets/images/psloader/base64decoded_layer2.png){:class="img-responsive"}

1) bytearray contents are decrypted in a for loop with 1 byte hardcoded xor key

![image](/assets/images/psloader/layer2_xor.png){:class="img-responsive"}

2) decrypted contents are stored as ASCII string in another variable in order to be able to create scriptblock for decrypted contents and execute it using Invoke-Command cmdlet

![image](/assets/images/psloader/layer2_scriptblock.png){:class="img-responsive"}

but I shall also modify second layer to get decrypted layer three contents and dump result into another output file as shown in the figure below

![image](/assets/images/psloader/layer2processing.png){:class="img-responsive"}

decryptedlayer3.ps1 now contains the obfuscated layer three powershell script embedding ransomware dlls in bytearrays and other commands to process the malicious payload

![image](/assets/images/psloader/dlls.png){:class="img-responsive"}

<h1>Processing Obfuscated layer 3</h1>

Let's start digging into layer three powershell script which is quite obfuscated having lengthy and random string variable and routine names responsible to drop final payload. It is required to perform following steps in order to execute Netwalker ransomware on victim's machine


- define variables to invoke in-memory Windows API function calls without compilation
- define routines to load dll without using Windows loader
- detect environment
- get PID of a legitimate process from a list of running processes and inject payload via custom loader
- delete shadow copies

First off, it defines required variables and routines:

<b> to invoke in-memory Windows API function calls without compilation,</b> C# code to declare structs and enums for memory manipulation is defined inside a variable as shown below

![image](/assets/images/psloader/Csharpcode.png){:class="img-responsive"}

and to invoke kernell32.dll APIs using wrapper .Net methods available in powershell

![image](/assets/images/psloader/DLLImports.png){:class="img-responsive"}

final command in this case will let us instantiate objects by making Microsoft .Net core classes available in our powershell session and ensure ransomware's true memory residence through reflection. 

Following set of routines help <b>correctly compute required memory addresses and relocations</b> by casting integer datatypes (signed integers to Unsigned integers and vice versa) so that the script could act as its own custom loader and load dll without using Windows loader

![image](/assets/images/psloader/conversions.png){:class="img-responsive"}

Finally it defines a bunch of routines to write embedded malicious binary into another process's memory and execute it.

Script starts its execution by detecting underlying processor's architecture to know whether it is running on x86 or amd64 and to prepare 32-bit or 64-bit dll accordingly using following if-else block 

{% highlight powershell %}
[byte[]]$EbihwfodUZMKtNCBx = $ptFvKdtq
$aukhgaZFiPJBarSpJc = $false
if ( ( Get-WmiObject Win32_processor).AddressWidth -eq 64 )
{
 [byte[]]$EbihwfodUZMKtNCBx = $GxwyKvgEkr
 $aukhgaZFiPJBarSpJc = $true    
 if ( $env:PROCESSOR_ARCHITECTURE -ne 'amd64' )
    {
      if ($myInvocation.Line) 
         {
            &"$env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -ExecutionPolicy ByPass -NoLogo -NonInteractive -NoProfile -NoExit $myInvocation.Line
         }
      else
         {
            &"$env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -ExecutionPolicy ByPass -NoLogo -NonInteractive -NoProfile -NoExit -file "$($myInvocation.InvocationName)" $args
         }
      exit $lastexitcode
    }
}
{% endhighlight %}

later it allocates memory in current process's address space and starts writing dll on the allocated memory using following for loop

{% highlight powershell %}
for( $dxQpkwU = 0; $dxQpkwU -lt $TKgfkdkQrLMAN.KGcnFrQVhkckQriBC.nKkeCknfm; $dxQpkwU++ )
{
    $PdWhwldJHtQhtsMJe = [System.Runtime.InteropServices.Marshal]::PtrToStructure( $lItUIbvCvHxzMmrKtX,[Type][Fvh.wTEWKRjOqBX] )
    $rZKYDiOJE  = RBeMnMHvnbNEob $eIr $( ULhnbcyXERLvVtGXUp $PdWhwldJHtQhtsMJe.sUtYsMhA )
    $MxyiIYGMhxakrDbKyjL = RBeMnMHvnbNEob $upEcLTMCGhc $( ULhnbcyXERLvVtGXUp $PdWhwldJHtQhtsMJe.cymIspbCOaY )
    $mofiZSsnxylxNuA = $AaauDVCQMlKUXx::PMUN( $VxxHhZYpWSgsPvKNuDx, $MxyiIYGMhxakrDbKyjL, $rZKYDiOJE, $PdWhwldJHtQhtsMJe.mkvugoDzrJgTSSJp, [ref]([UInt32]0 ) )
   
    if ( $mofiZSsnxylxNuA -eq $false )
       {
         return
       }
    $lItUIbvCvHxzMmrKtX = RBeMnMHvnbNEob $lItUIbvCvHxzMmrKtX $([System.Runtime.InteropServices.Marshal]::SizeOf([Type][Fvh.wTEWKRjOqBX]))
}
{% endhighlight %}

snapshot of object containig dll that gets written into current process's memory

![image](/assets/images/psloader/dll_struct.png){:class="img-responsive"}

after that it calls following routine with certain parameters to inject payload by specifying a legitimate target process which is 'explorer.exe' in this case along with memory location pointer for buffer containg Dll and size of the buffer containing dll

![image](/assets/images/psloader/call_explorer.png){:class="img-responsive"}

this routine finds PID of explorer.exe form a list of running processes and passes obtained PID to final routine

![image](/assets/images/psloader/get_explorer_pid.png){:class="img-responsive"}

which first reflectively injects ransomware dll into explorer.exe by allocating a chunk of memory of specified size into its address space and writing ransomware dll on the allocated memory and then executes it by creating a thread that runs in the virtual address space of Explorer.exe process

![image](/assets/images/psloader/inject.png){:class="img-responsive"}

and in the end deletes shadow copies of the data being held on the system at that particular time to completely eliminate any possibility of recovering it and performs required memory cleanup using following set of commands

![image](/assets/images/psloader/delete_shadowcopy.png){:class="img-responsive"}

as soon as script exits, <b>FE026B-Readme.txt</b> window appears on the system with ransom message and all encrypted files with fe026b extension are no longer accessible

![image](/assets/images/psloader/message.png){:class="img-responsive"}


<strong><em>Note: </em></strong><i>Ransomware dll being injected can be dumped into a binary file in powershell script, which has SHA-256 [302ff75667460accbbd909275cf912f4543c4fb4ea9f0d0bad2f4d5e6225837b][md5-e17951ccd3f30ef2ecc7963628210a5e] hash but it can be seen that it is 64-bit PE file and first two bytes in this case have wrong hex value <b>0xDEAD</b></i>

![image](/assets/images/psloader/dumped.png){:class="img-responsive"}

replacng first two bytes <b>0xDEAD</b> with <b>0x4D5A</b> in DOS header in HxD editor would result in Netwalker ransomware dll with [f93209fccd0c452b8b5dc9db46341281344156bbedd23a47d2d551f80f460534][md5-f5c877335920f0ef040228e18b426d00] SHA-256 hash.


<h1>Deciphering Netwalker x86-64 DLL</h1>


Let's load final dll in IDA and perform basic static analysis first, I'll start by looking up for strings, but they are mostly useless, moreover, it has only one export i.e., main entry which seems to implement all its functionality

![image](/assets/images/netwalker/exports.png){:class="img-responsive"}

second important thing to note here is that it has no <n>imports address table</n>, which implies that it might be obfuscating APIs or strings with some hashing or encryption algorithm, this can be verified by loading the dll in <b>PEiD</b> and looking for possible algorithms in its <b>K</b>rypto <b>ANAL</b>yzer plugin which shows multiple references to different encoding, hashing and encrypt/decrypt algorithms in dll as shown in the figure below

![image](/assets/images/netwalker/algo_references.png){:class="img-responsive"}

If I randomly pick a CRC32 reference and look it up in dll, it is found in <b>sub_180005D60</b> routine being used in a loop

![image](/assets/images/netwalker/crc32_loop.png){:class="img-responsive"}

do-while loop in decompiled routine shows <b>CRC32 division flow</b>

![image](/assets/images/netwalker/decompiled_crc32.png){:class="img-responsive"}

let's rename this routine to <b>crc32_checksum</b> and look for its cross references, result shows it is cross referenced two times in <b>sub_180001000</b>, if this routine is subsequently checked for further cross references, it shows <b>~165</b> references

![image](/assets/images/netwalker/decrypt_strings_xrefs.png){:class="img-responsive"}

we can assume here that the routine <b>sub_180001000</b> being cross referenced <b>~165</b> times is possibly decrypting strings, I'll rename it to <b>decrypt_strings</b>


now let's take a closer look at <b>sub_180001490</b> routine which almost has all the Xrefs to <b>decrypt_strings</b>, following code shows it is taking two arguments v1, which is being used in all of its calls and a 4-byte hex value which seems to be CRC32 hash and retrun value is being stored to different offsets of an array 

![image](/assets/images/netwalker/resolve_Pis_initial_.png){:class="img-responsive"}

this routine has multiple similar code blocks but with different hash values, here it can be assumed that it is decrypting APIs from different libraries, let's rename it to <b>resolve_imports</b> and look for its Xrefs which leads to DLL's main <b>DllEntryPoint</b> routine - now it's time to look into it dynamically.

First routine that is being called by DLL is <b>resolve_imports</b>, which in turn calls <b>sub_180001310</b> routine, it is taking <b>0x84C05E40</b> hash value as parameter, a quick Google search shows it is for <b>"ntdll.dll"</b> which can also be verified with Python

![image](/assets/images/netwalker/python_ntdll_crc32.png){:class="img-responsive"}

this routine returns handle for <b>ntdll.dll</b> library, later it takes another hash value <b>0xA1D45974</b> which is resolved to <b>RtlAllocateHeap</b> API, it is first called to allocate a block of memory on heap to later store resolved addresses there on different array indexes

![image](/assets/images/netwalker/get_ntdll_handle.png){:class="img-responsive"}

this routine decrypts and resolves serveral APIs from ntdll.dll, kernel32.dll, advapi32.dll, use32.dll, mpr.dll, shell32.dll, netapi32.dll, ole32.dll, oleaut32.dll and psapi.dll libraries. I wrote a simple IDAPython script [here][here] which resolves CRC32 hashes and adds resolved value in comment

![image](/assets/images/netwalker/resolved.png){:class="img-responsive"}

after resolving imports, it continues to check for stomped MZ header <b>0xDEAD</b> by first copying header value <b>0xDEAD</b> in eax, setting up rbx with a certain address and later subtracting 0x400 from rbx in each iteration to reach image's base address as shown by the loop in figure below

![image](/assets/images/netwalker/stomped_MZ_header.png){:class="img-responsive"}

if <b>0xDEAD</b> header value is intact (i.e., making sure DLL is being run <b>injected</b> in <b>explorer.exe</b>), it continues further to fix <b>MZ</b> header in memory and read image's resources - otherwise it'll throw <b>ACCESS_VIOLATION</b> exception and exits

![image](/assets/images/netwalker/loadresource.png){:class="img-responsive"}

after required resource has been loaded in memory, <b>sub_18000EAF0</b> routine processes it by first extracting first 4 bytes of data which is probably length of key, next 7 bytes (cZu-H!<) are extracted as <b>RC4 key</b> which is being used to decrypt rest of the payload - following code from <b>sub_18000EAF0</b> routine implemets <b>3</b> recognizable RC4 loops <b>1.</b> Initialization (creating <b>Substitution Box</b>) <b>2.</b> <b>Scrambling Substitution</b> box with key to generate a <b>pseudo-random</b> keystream <b>3.</b> <b>xoring</b> keystream with rest of the data

![image](/assets/images/netwalker/rc4_decrypt.png){:class="img-responsive"}

decrypted data seems to be malware's embedded <b>configuration</b> in <b>json</b> format

![image](/assets/images/netwalker/malw-config.png){:class="img-responsive"}

this can also be verified by copying resource as hex string along with 7-byte hex key on Cyberchef

![image](/assets/images/netwalker/cyberchef_recipe.png){:class="img-responsive"}

next routine <b>sub_180004600</b> parses configuration to get list of file extensions which needs to be encrypted, default paths and files that should be whitelisted, attacker's ToR info and ransomware note along with ransomware note file name and format, subsequent routines decrypt ransom note with AES decryption algorithm by using 256-bit hardcoded key, checks running processes to kill any blacklisted process and eventually performs ransomware activity.

That's it. See you next time.

<strong>Sources:</strong>
1. https://blog.trendmicro.com/trendlabs-security-intelligence/netwalker-fileless-ransomware-injected-via-reflective-loading/
2. https://any.run/report/f4656a9af30e98ed2103194f798fa00fd1686618e3e62fba6b15c9959135b7be/ca44ad38-0e46-455e-8cfd-42fb53d41a1d

[netwalker-ransomware]: https://labs.sentinelone.com/netwalker-ransomware-no-respite-no-english-required/
[fileless-attacks]: https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/security-101-how-fileless-attacks-work-and-persist-in-systems
[link-to-download-ps1-loader]: https://bazaar.abuse.ch/download/f4656a9af30e98ed2103194f798fa00fd1686618e3e62fba6b15c9959135b7be/
[md5-e17951ccd3f30ef2ecc7963628210a5e]: https://www.virustotal.com/gui/file/302ff75667460accbbd909275cf912f4543c4fb4ea9f0d0bad2f4d5e6225837b/detection
[md5-f5c877335920f0ef040228e18b426d00]: https://www.virustotal.com/gui/file/f93209fccd0c452b8b5dc9db46341281344156bbedd23a47d2d551f80f460534/detection
[here]: https://github.com/xer0xE9/IDAPython_scripts/blob/master/netwalker_crc32hash_resolver.py