---
layout: post
title:  "A tale of Netwalker Powershell reflective loader - Part 1"
date:   2020-12-21
categories: loaders netwalker
---

Hi! I lately started delving into powershell loaders and came across a really intriguing powershell loader for "Netwalker ransomware" [[1]][1-netwalker-ransomware], performing fileless attack [[2]][2-fileless-attacks] where ransomware binary directly loads and executes malicious payload in memory without actually storing it on disk leaving no trace of execution. This post thoroughly discusses how first stage powershell script filelessly loads and executes embedded payload through reflective Dll injection.

SHA-256 of the sample being analyzed:  [f4656a9af30e98ed2103194f798fa00fd1686618e3e62fba6b15c9959135b7be][link-to-download-ps1-loader]

-----------------------------------------------------------------------------------------------------------------------------------
Prior knowledge required:

- Basic Powershell understanding
- using .NET reflection to access Windows API in PowerShell
- Windows APIs for Process/Dll injection
    
-----------------------------------------------------------------------------------------------------------------------------------


This is around ~5 MBs of powershell script using three layers of encoding, encryption and obfuscation respectively to hide ransomware dll and supporting powershell commands for reflective Dll injection. The uppermost layer executes very long base64 encoded command (screenshot covers only a small portion of this command)

![image](/assets/images/psloader/layer1.png){:class="img-responsive"}

<h1>Processing Base64 encoded layer 1</h1>

In order to get decoded output from initial script, I shall run powershell script into my VM’s Powershell ISE but as the Invoke-Expression cmdlet will process base64-encoded payload and execute the ransomware therefore, I'll modify the script by replacing this comdlet with a variable to store result of base64 decoded command and dump output in a file as shown in the figure below

![image](/assets/images/psloader/layer1processing.png){:class="img-responsive"}


<h1>Processing Encrypted layer 2</h1>

base64 decoded second layer once again contains a very long bytearray which is processed in two steps

![image](/assets/images/psloader/base64decoded_layer2.png){:class="img-responsive"}

1) bytearray contents are decrypted in a for loop with 1 byte hardcoded xor key

![image](/assets/images/psloader/layer2_xor.png){:class="img-responsive"}

2) decrypted contents are stored as ASCII string in another variable in order to be able to create scriptblock for decrypted contents and execute it using Invoke-Command cmdlet

![image](/assets/images/psloader/layer2_scriptblock.png){:class="img-responsive"}

I shall also modify second layer to get decrypted layer three contents and dump result into another output file as shown in the figure below

![image](/assets/images/psloader/layer2processing.png){:class="img-responsive"}

decryptedlayer3.ps1 now contains the obfuscated layer three powershell script embedding ransomware dlls in bytearrays and other commands to process the malicious payload

![image](/assets/images/psloader/dlls.png){:class="img-responsive"}

<h1>Processing Obfuscated layer 3</h1>

Layer three powershell loader contains obfuscated variable and routine names. It is required to perform following steps to load embedded executable into memory


- define variables to invoke in-memory Windows API function calls without compilation
- define routines to load dll without using Windows loader
- detect environment
- get PID of a legitimate process from a list of running processes and inject payload via custom loader
- delete shadow copies

First off, it defines required variables and routines:

<b> to invoke in-memory Windows API function calls without compilation,</b> a set of variables define C# code to declare structs and enums for memory manipulation 

![image](/assets/images/psloader/C#code.png){:class="img-responsive"}

and to invoke kernell32.dll APIs using wrapper .Net methods available in powershell

![image](/assets/images/psloader/DLLImports.png){:class="img-responsive"}

final command in this case will let us instantiate objects by making Microsoft .Net core classes available in our powershell session and ensure ransomware's true memory residence through reflection. 

and following set of routines <b>correctly compute required memory addresses and relocations</b> by mapping integer data types (signed integers to Unsigned integers and vice versa) 

![image](/assets/images/psloader/conversions.png){:class="img-responsive"}

Finally it defines a bunch of routines to process and load embedded malicious payload.

Script starts its execution by detecting processor's architecture whether it is x86 or amd64 to prepare 32-bit or 64-bit dll accordingly using following if-else block 

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

later it allocates memory in current process's address space and starts writing dll on the allocated memory using for loop

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

after that it calls following routine with certain parameters to inject payload into a legitimate process which is 'explorer.exe' in this case along with memory location pointer for buffer containg Dll and size of the buffer containing dll

![image](/assets/images/psloader/call_explorer.png){:class="img-responsive"}

this routine finds PID of explorer.exe form a list of running processes and passes obtained PID to final routine

![image](/assets/images/psloader/get_explorer_pid.png){:class="img-responsive"}

which first reflectively injects ransomware dll into explorer.exe and then executes it by creating a thread that runs in the virtual address space of Explorer.exe process

![image](/assets/images/psloader/inject.png){:class="img-responsive"}

and in the end deletes shadow copies of the data being held on the system at that particular time to completely eliminate any possibility of recovering it and performs required memory cleanup using following set of commands

![image](/assets/images/psloader/delete_shadowcopy.png){:class="img-responsive"}

as soon as script exits FE026B-Readme.txt window appears on the system with ransom message and all encrypted files with fe026b extension are no longer accessible

![image](/assets/images/psloader/message.png){:class="img-responsive"}


<strong><em>Note: </em></strong><b>Ransomware dll being injected can be dumped into a binary file having SHA-256 [302ff75667460accbbd909275cf912f4543c4fb4ea9f0d0bad2f4d5e6225837b][md5-e17951ccd3f30ef2ecc7963628210a5e] hash but it can be seen that first two bytes in this case contain wrong hex value 0xADDE</b>

![image](/assets/images/psloader/dumped.png){:class="img-responsive"}

replacng first two bytes <b>0xADDE</b> with <b>0x4D5A</b> in MZ header would result in Netwalker ransomware with [f93209fccd0c452b8b5dc9db46341281344156bbedd23a47d2d551f80f460534][md5-f5c877335920f0ef040228e18b426d00] SHA-256 hash.

and that's it. I hope you liked this writeup on disecting the powershell reflective loader.

Best regards,

./$bash.

[link-to-download-ps1-loader]: https://bazaar.abuse.ch/download/f4656a9af30e98ed2103194f798fa00fd1686618e3e62fba6b15c9959135b7be/
[1-netwalker-ransomware]: https://labs.sentinelone.com/netwalker-ransomware-no-respite-no-english-required/
[2-fileless-attacks]: https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/security-101-how-fileless-attacks-work-and-persist-in-systems

[md5-e17951ccd3f30ef2ecc7963628210a5e]: https://www.virustotal.com/gui/file/302ff75667460accbbd909275cf912f4543c4fb4ea9f0d0bad2f4d5e6225837b/detection
[md5-f5c877335920f0ef040228e18b426d00]: https://www.virustotal.com/gui/file/f93209fccd0c452b8b5dc9db46341281344156bbedd23a47d2d551f80f460534/detection

<strong>Sources:</strong>
1. https://blog.trendmicro.com/trendlabs-security-intelligence/netwalker-fileless-ransomware-injected-via-reflective-loading/
2. https://any.run/report/f4656a9af30e98ed2103194f798fa00fd1686618e3e62fba6b15c9959135b7be/ca44ad38-0e46-455e-8cfd-42fb53d41a1d