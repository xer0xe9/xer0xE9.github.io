---
layout: post
title:  "Netwalker: from Powershell reflective loader to injected Dll"
date:   2021-06-10
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


<strong>Deciphering Netwalker x86-64 DLL</strong>


Let's load final dll in IDA and perform basic static analysis first, I'll start by looking up for strings, but they are mostly useless, moreover, it has only one export i.e., main entry which seems to implement all its functionality

![image](/assets/images/netwalker/exports.png){:class="img-responsive"}

second important thing to note here is that it has no <n>imports address table</n>, which implies that it might be obfuscating APIs or strings with some hashing or encryption algorithm, this can be verified by loading the dll in <b>PEiD</b> and looking for possible algorithms in its <b>Krypto ANALyzer plugin</b> which shows multiple references to different encoding, hashing and encrypt/decrypt algorithms in dll as shown in the figure below

![image](/assets/images/netwalker/algo_references.png){:class="img-responsive"}

If I randomly pick a CRC32 reference and look it up in dll, it is found in <b>sub_180005D60</b> routine being used in a loop along with other constant values

![image](/assets/images/netwalker/crc32_loop.png){:class="img-responsive"}

a do-while loop in decompiled routine shows <b>CRC32 division flow</b>

![image](/assets/images/netwalker/decompiled_crc32.png){:class="img-responsive"}

let's rename this routine to <b>crc32_checksum</b> and look for its cross references, result shows it is cross referenced two times in <b>sub_180001000</b>, if this routine is subsequently checked for further cross references, it shows <b>~165</b> references

![image](/assets/images/netwalker/decrypt_strings_xrefs.png){:class="img-responsive"}

we can assume here that the routine <b>sub_180001000</b> being cross referenced <b>~165</b> times is possibly decrypting strings, I'll rename it to <b>decrypt_strings</b>


now let's take a close look at <b>sub_180001490</b> routine which almost has all the Xrefs to <b>decrypt_strings</b>, following code shows it is taking two arguments v1, which is being used in all of its calls and a 4-byte hex value which seems to be CRC32 hash and retrun value is being stored to different offsets of an array 

{% highlight c++ %}
var_rtlAllocHeap_ = (__int64 (__fastcall *)(_QWORD, signed __int64, signed __int64))decrypt_strings_sub_180001000(var_h_ntdll,0xA1D45974);

  if ( !var_rtlAllocHeap_ )
    return (unsigned int)dword_1800171E0;
  qword_1800171E8 = var_rtlAllocHeap_(*(_QWORD *)(__readgsqword(0x60u) + 0x30), 8i64, 0x510i64);
  if ( !qword_1800171E8 )
    return (unsigned int)dword_1800171E0;
  *(_QWORD *)qword_1800171E8 = decrypt_strings_sub_180001000(v1, 0xA1D45974);
  *(_QWORD *)(qword_1800171E8 + 8) = decrypt_strings_sub_180001000(v1, 0xAF11BC24);
  *(_QWORD *)(qword_1800171E8 + 16) = decrypt_strings_sub_180001000(v1, 0xB973B8DC);
  *(_QWORD *)(qword_1800171E8 + 24) = decrypt_strings_sub_180001000(v1, 0x8463960A);
  *(_QWORD *)(qword_1800171E8 + 32) = decrypt_strings_sub_180001000(v1, 0xD141AFD3);
  *(_QWORD *)(qword_1800171E8 + 40) = decrypt_strings_sub_180001000(v1, 0x57F17B6B);
  *(_QWORD *)(qword_1800171E8 + 48) = decrypt_strings_sub_180001000(v1, 0x23398D9A);
  *(_QWORD *)(qword_1800171E8 + 72) = decrypt_strings_sub_180001000(v1, 0xBD6735C3);
  *(_QWORD *)(qword_1800171E8 + 80) = decrypt_strings_sub_180001000(v1, 0x900F6A6E);
  *(_QWORD *)(qword_1800171E8 + 56) = decrypt_strings_sub_180001000(v1, 0xA8AE7412);
  *(_QWORD *)(qword_1800171E8 + 64) = decrypt_strings_sub_180001000(v1, 0x4896A43);
  *(_QWORD *)(qword_1800171E8 + 88) = decrypt_strings_sub_180001000(v1, 0x4C8A5B22);
  *(_QWORD *)(qword_1800171E8 + 96) = decrypt_strings_sub_180001000(v1, 0x61E2048F);
  *(_QWORD *)(qword_1800171E8 + 104) = decrypt_strings_sub_180001000(v1, 0x52FF8A3F);
  *(_QWORD *)(qword_1800171E8 + 112) = decrypt_strings_sub_180001000(v1, 0xA312E4DE);
  *(_QWORD *)(qword_1800171E8 + 120) = decrypt_strings_sub_180001000(v1, 0xCA3A8F9A);
  *(_QWORD *)(qword_1800171E8 + 128) = decrypt_strings_sub_180001000(v1, 0x958F47AF);
  *(_QWORD *)(qword_1800171E8 + 136) = decrypt_strings_sub_180001000(v1, 0x9AB4737E);
  *(_QWORD *)(qword_1800171E8 + 144) = decrypt_strings_sub_180001000(v1, 0x7EF4BAE5);
  *(_QWORD *)(qword_1800171E8 + 152) = decrypt_strings_sub_180001000(v1, 0x4A5A980C);
  *(_QWORD *)(qword_1800171E8 + 160) = decrypt_strings_sub_180001000(v1, 0x7AA7B69B);
  *(_QWORD *)(qword_1800171E8 + 168) = decrypt_strings_sub_180001000(v1, 0x4491B126);
  *(_QWORD *)(qword_1800171E8 + 176) = decrypt_strings_sub_180001000(v1, 0x27AE6B27);
  *(_QWORD *)(qword_1800171E8 + 184) = decrypt_strings_sub_180001000(v1, 0x43681CE6);
  *(_QWORD *)(qword_1800171E8 + 192) = decrypt_strings_sub_180001000(v1, 0x58016551);
  *(_QWORD *)(qword_1800171E8 + 200) = decrypt_strings_sub_180001000(v1, 0x183679F2);
  *(_QWORD *)(qword_1800171E8 + 208) = decrypt_strings_sub_180001000(v1, 0x6AB0C8E4);
  *(_QWORD *)(qword_1800171E8 + 216) = decrypt_strings_sub_180001000(v1, 0x97FD2398);
  *(_QWORD *)(qword_1800171E8 + 224) = decrypt_strings_sub_180001000(v1, 0xDBF381B5);
  *(_QWORD *)(qword_1800171E8 + 232) = decrypt_strings_sub_180001000(v1, 0xC67A0958);
  *(_QWORD *)(qword_1800171E8 + 240) = decrypt_strings_sub_180001000(v1, 0x94FCB0C0);
  *(_QWORD *)(qword_1800171E8 + 256) = decrypt_strings_sub_180001000(v1, 0xE0762FEB);
  *(_QWORD *)(qword_1800171E8 + 264) = decrypt_strings_sub_180001000(v1, 0xE9D6CE5E);
  *(_QWORD *)(qword_1800171E8 + 272) = decrypt_strings_sub_180001000(v1, 0x5C2D1A97);
  *(_QWORD *)(qword_1800171E8 + 280) = decrypt_strings_sub_180001000(v1, 0xE4879939);
  *(_QWORD *)(qword_1800171E8 + 288) = decrypt_strings_sub_180001000(v1, 0x81223212);
  *(_QWORD *)(qword_1800171E8 + 296) = decrypt_strings_sub_180001000(v1, 0x3F6F38C);
  *(_QWORD *)(qword_1800171E8 + 304) = decrypt_strings_sub_180001000(v1, 0x9EEE4B80);
  *(_QWORD *)(qword_1800171E8 + 312) = decrypt_strings_sub_180001000(v1, 0xA4163EBC);
  *(_QWORD *)(qword_1800171E8 + 320) = decrypt_strings_sub_180001000(v1, 0x90483FF6);
  *(_QWORD *)(qword_1800171E8 + 328) = decrypt_strings_sub_180001000(v1, 0xD3534981);
  *(_QWORD *)(qword_1800171E8 + 336) = decrypt_strings_sub_180001000(v1, 0xE1453B98);
  *(_QWORD *)(qword_1800171E8 + 344) = decrypt_strings_sub_180001000(v1, 0x6273B572);
  *(_QWORD *)(qword_1800171E8 + 352) = decrypt_strings_sub_180001000(v1, 0xB19AB602);
  *(_QWORD *)(qword_1800171E8 + 360) = decrypt_strings_sub_180001000(v1, 0x235B0390);
  *(_QWORD *)(qword_1800171E8 + 368) = decrypt_strings_sub_180001000(v1, 0xD09C750);
  *(_QWORD *)(qword_1800171E8 + 248) = decrypt_strings_sub_180001000(v1, 0x3A14841F);
  *(_QWORD *)(qword_1800171E8 + 376) = decrypt_strings_sub_180001000(v1, 0x62EA7CB7);
  *(_QWORD *)(qword_1800171E8 + 384) = decrypt_strings_sub_180001000(v1, 0xF675D37D);
  *(_QWORD *)(qword_1800171E8 + 392) = decrypt_strings_sub_180001000(v1, 0xD23B7C02);
  *(_QWORD *)(qword_1800171E8 + 400) = decrypt_strings_sub_180001000(v1, 0x59B1E5AD);
  *(_QWORD *)(qword_1800171E8 + 408) = decrypt_strings_sub_180001000(v1, 0xA1B1DC21);
  *(_QWORD *)(qword_1800171E8 + 416) = decrypt_strings_sub_180001000(v1, 0x5368361B);
  *(_QWORD *)(qword_1800171E8 + 424) = decrypt_strings_sub_180001000(v1, 0xCACBBC36);

{% endhighlight %}

this routine has multiple similar code blocks but with different hash values, here it can be assumed it is decrypting APIs from different libraries, let's rename it to <b>API_hashing</b> and look for its Xrefs which lead to DLL's main <b>DllEntryPoint</b> routine - now it's time to look into it dynamically for our assumptions.

<strong>Sources:</strong>
1. https://blog.trendmicro.com/trendlabs-security-intelligence/netwalker-fileless-ransomware-injected-via-reflective-loading/
2. https://any.run/report/f4656a9af30e98ed2103194f798fa00fd1686618e3e62fba6b15c9959135b7be/ca44ad38-0e46-455e-8cfd-42fb53d41a1d

[netwalker-ransomware]: https://labs.sentinelone.com/netwalker-ransomware-no-respite-no-english-required/
[fileless-attacks]: https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/security-101-how-fileless-attacks-work-and-persist-in-systems
[link-to-download-ps1-loader]: https://bazaar.abuse.ch/download/f4656a9af30e98ed2103194f798fa00fd1686618e3e62fba6b15c9959135b7be/
[md5-e17951ccd3f30ef2ecc7963628210a5e]: https://www.virustotal.com/gui/file/302ff75667460accbbd909275cf912f4543c4fb4ea9f0d0bad2f4d5e6225837b/detection
[md5-f5c877335920f0ef040228e18b426d00]: https://www.virustotal.com/gui/file/f93209fccd0c452b8b5dc9db46341281344156bbedd23a47d2d551f80f460534/detection