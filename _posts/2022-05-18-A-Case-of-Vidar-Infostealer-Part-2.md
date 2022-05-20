---
layout: post
title:  "A Case of Vidar Infostealer - Part 2"
date:   2022-05-18
categories: Infostealers
---

Hi, welcome to the Part 2 of my Vidar infostealer analysis writeup. In [part 1][link-to-part-1] of this post, I covered detailed technical analysis of packed executable dropped by initial stager by extracting and exploring embedded shellcode which is unpacking and self-injecting final payload. This part focuses on detailed static analysis of final injected payload: unpacked Vidar infostealer, defying anti-analysis techniques employed by malware (string decryption, dynamically loading DLLs and resolving APIs), automating analysis and finally uncovering stealer's main functionality through deobfuscated/decrypted strings.


<b>SHA256:</b> [fca48ccbf3db60291b49f2290317b4919007dcc4fb943c1136eb70cf998260a5][link-to-download-unpacked-exe]

<STRONG>Vidar in a Nutshell</STRONG>

The Vidar Stealer is popular stealer written in C++ and has been active since October 2018 and seen in numerous different campaigns. It has been utilized by the threat actors behind GandCrab to use Vidar infostealer in the process for distributing the ransomware as second stage payload, which helps increasing their profits. The family is quite flexible in its operations as it can be configured to grab specific information dynamically. It fetches its configuration
from C2 server at runtime which dictates what features are activated and which information is gathered and exfiltrated from victim machine. It also downloads several benign supporting dlls (freebl3.dll, mozglue.dll, msvcp140.dll and nss3.dll) to process encrypted data from browsers such as email credentials, chat account details, web-browsing cookies, etc., compresses everything into a ZIP archive, and then exfiltrates the archive to the attackers via an HTTP POST request. Once this is done, it kills its own process and deletes the downloaded DLLs and the main executable in an attempt to wipe all evidence of its presence from the victim’s machine.

<STRONG>Technical Analysis</STRONG>

I'll start analysis by loading this executable directly in IDA to look for important strings, IDA's strings window show some intersting plaintext and base64 encoded strings stored in .rdata section

![image](/assets/images/vidar/strings.png){:class="img-responsive"}

if I quickly decode few base64 strings in Cyberchef, it results in junk data giving a clue that strings are possibly encrypted before they were base64 encoded

![image](/assets/images/vidar/cyberchef_base64decod.png){:class="img-responsive"}

next I'll check for encryption algorithm but KANAL fails to detect any potential algorithm for string encryption as given in figure below

![image](/assets/images/vidar/list_of_algorithms.png){:class="img-responsive"}

so let's start digging it statically to see how string encryption actually works in this case, for this purpose I'll double click a base64 encoded string randomly to see where it's been used by finding its Xrefs which takes us to <b>sub_423050</b> routine

![image](/assets/images/vidar/wrapper_string_decryption_routine.png){:class="img-responsive"}

this routine seems to be processing most of the base64 encoded strings and storing result for each processed string in a global variable, apart from first two variables which seem to be storing plaintext values for possible decryption key and domain, let's rename this routine to <b>wrap_decrypt_strings</b>

![image](/assets/images/vidar/decompiled_decrypt_strings.png){:class="img-responsive"}

<b>sub_422F70</b> in <b>wrap_decrypt_strings</b> routine can be seen from figure above to be repititively called with base64 strings, has been Xref'd for ~400 times, it can be assumed it is processing encrypted strings and can be renamed to <n>decrypt_strings</n> for our convenience as shown in the figure below

![image](/assets/images/vidar/wrapper_renamed_strings.png){:class="img-responsive"}

further exploring <b>decrypt_strings</b> by loading the executable in x64dbg, debugging unveils that first two calls to <b>sub_4011C0</b> routine are just copying values of key and base64 encoded encrypted string to local variables, next routine <b>sub_422D00</b> is decoding base64 string, stores decoded hex value to a local variable and returns address of this local variable

![image](/assets/images/vidar/base64_decoding.png){:class="img-responsive"}

base64 decoded hex string can also be verified in cyberchef

![image](/assets/images/vidar/cyberchef_hex_b64_decode.png){:class="img-responsive"}

later it calculates length for base64 decoded hex string and allocates buffer equivalent of that length on heap, next two calls to <b>sub_401330</b> routine are allocating two buffers on heap for key and base64 decoded hex string respectively before it proceeds to finally decrypt data using <b>sub_422980</b>, quick decompilation of code for this routine results in three well recognized <b>RC4</b> loops

![image](/assets/images/vidar/RC4_decrypt_decompiled.png){:class="img-responsive"}

string decryption can be confirmed by following Cyberchef recipe

![image](/assets/images/vidar/cyberchef_RC4_decrypt.png){:class="img-responsive"}

decompiled version of <b>decrypt_strings</b> routine sums up all steps described above

![image](/assets/images/vidar/decompiled_decrypt_strings_routine.png){:class="img-responsive"}

once processing for <b>wrap_decrypt_strings</b> completes, it continues to process next routine from <b>_WinMain</b>, a quick overview of <b>sub_419700</b> this routine reveals that it makes extensive use of global variables which were initialized in <b>wrap_decrypt_strings</b> apart from two calls to <b>sub_4196D0</b> and <b>sub_4195A0</b> routines respectively which can further be explored by debugging

![image](/assets/images/vidar/load_kernel32_dll.png){:class="img-responsive"}

in the figure above, routine <b>sub_4196D0</b> is parsing PEB structure to get base address for Kernel32.dll loaded in memory by accessing _PEB -> PEB_LDR_DATA -> InLoadOrderModuleList structures respetively, next routine <b>sub_4195A0</b> being called is taking two parametes: 1). kernel32.dll base address 2). address of a global variable dword_432204 (LoadLibraryA) in first call and dword_432438 (GetProcAddress) in second call

![image](/assets/images/vidar/calls.png){:class="img-responsive"}

where <b>sub_4195A0</b> is parsing kernel32.dll's header by navigating from IMAGE_DOS_HEADER -> IMAGE_NT_HEADER -> IMAGE_OPTIONAL_HEADER.DATA_DIRECTORY -> IMAGE_EXPORT_DIRECTORY.AddressOfNames to retrieve export name and compare it with value of API contained by variable which in this case is LoadLibraryA

![image](/assets/images/vidar/parse_PE_hdr.png){:class="img-responsive"}

if both strings match, it returns API's address by accessing value of IMAGE_EXPORT_DIRECTORY.AddressOfFunctions field, resolved address is stored in <b>dword_432898</b> variable while second call to <b>sub_4195A0</b> resolves GetProcAddress, stores resolved address to <b>dword_43280C</b> which is subsequently used to resolve rest of API functions at runtime. I wrote an IDAPython script [here][here] which is first decrypting strings from <b>wrap_decrypt_strings</b>, resolving APIs from <b>sub_419700</b> routine, adding comments and giving meaningful names to global variables storing resolved APIs to properly understand code flow and its functionality. decrypt_strings routine from IDAPython script is finding key, locating ~400 base64 encoded encrypted strings, base64 decoding strings and using key to decrypt base64 decoded hex strings, adding decrypted strings as comments and renaming variables as shown in figure below

![image](/assets/images/vidar/wrap_decrypt_strings_w_comments.png){:class="img-responsive"}

<b>resolve_apis</b> routine from script is resolving ~100 APIs from 11 libraries from <b>sub_419700</b> routine

![image](/assets/images/vidar/resolved_apis.png){:class="img-responsive"}

after resolving APIs, next routine <b>sub_41F4A0</b> checks if victime machine is part of CIS <b>(Commonwealth of Independent States)</b> countries which include Armenia, Azerbaijan, Belarus, Georgia, Kazakhstan, Kyrgyzstan, Moldova, Russia, Tajikistan, Turkmenistan, Ukraine, and Uzbekistan, it retrieves  language ID for current user by calling GetUserDefaultLangID API and compares returned result with specified location codes

![image](/assets/images/vidar/CIS_check.png){:class="img-responsive"}

where 0x43F corresponds to Kazakhstan, 0x443 to Uzbekistan, 0x82C to Azerbaijan and so on, it continues performing its tasks if user's language ID doesn't fall in the above mentioned category, otherwise it'll stop execution and exit, next routine <b>sub_41B700</b> performs windows defender anti-emulation check by compareing computer name to <b>HAL9TH</b> and user name to <b>JohnDoe</b> strings

![image](/assets/images/vidar/anti-emulation_check.png){:class="img-responsive"}

once all required checks are passed, <b>sub_420BE0</b> routine is called which consists of stealer's grabbing module, it prepares urls and destination path strings where downloaded dlls from C2 servers are to be stored before performing any other activity

![image](/assets/images/vidar/download_code_.png){:class="img-responsive"}

and then downloads <b>7</b> dlls under <b>C:\Programdata\\</b>

![image](/assets/images/vidar/urls.png){:class="img-responsive"}

next it creates its working directory under <b>C:\Programdata</b>, name of directory is randomly generated 15 digit string like <b>C:\ProgramData\920304972255009</b> where it further creates four sub-directories (autofill, cc, cookies and crypto) which are required to be created to store stolen data from browser, outlook, crypto currency wallets and system information gathering modules 

![image](/assets/images/vidar/steal_data_.png){:class="img-responsive"}

different types of browsers are being targeted to steal autofill, credit card, cookies, browsing history and victim's login credentials, this module is equipped with advanced stealing and encryption techniques  

![image](/assets/images/vidar/browser_info.png){:class="img-responsive"}

it further queries registry about SMTP and IMAP servers with confidential data and password, gathers data about connected outlook accounts (if any) and finally dumps all the data to outlook.txt file in its working directory

![image](/assets/images/vidar/gather_outlook_data.png){:class="img-responsive"}

later it scans for .wallet, .seco, .passphrase and .keystore files for <b>~30</b> cryptocurrency wallets on their installed paths and copies scanned files to "crypto" in working directory 

![image](/assets/images/vidar/wallets_info.png){:class="img-responsive"}

Vidar creates an HTTP POST request for C&C (http://himarkh.xyz/main.php) server in order to download configuration for grabber module at runtime, parses downloaded configuration and proceeds to gather host, hardware and installed software related info

![image](/assets/images/vidar/system_info.png){:class="img-responsive"}

which is stored in system.txt file according to the specified format as shown in figure below

![image](/assets/images/vidar/system_hardware_info.png){:class="img-responsive"}

the same routine also captures screenshots which is stored as "screenshot.jpg" inside working directory

![image](/assets/images/vidar/stolen_files_and_dirs.png){:class="img-responsive"}

immidiately after that a zip file with "_8294024645.zip" name format is created and stolen contents from working directory are compressed (file is compressed using Zip2 encryption algorithm as identified by KANAL)

![image](/assets/images/vidar/compressed_zip_file.png){:class="img-responsive"}

the compressed file is now ready to be exfiltrated to its C&C server in another POST request

![image](/assets/images/vidar/create_zip_file.png){:class="img-responsive"}

after exiting from recursive grabber module, it deletes downloaded DLLs and files fcreated in working directory being used to dump stolen data and information in order to remove its traces from victim machine

![image](/assets/images/vidar/delete_files_.png){:class="img-responsive"}

eventually it prepares a command <b>"/c taskkill /pid PID & erase EXECUTABLE_PATH & RD /S /Q WORKING_DIRECTORY_PATH\\* & exit"</b> which gets executed using cmd.exe to kill the running infostealer process and to delete remaining directories created by this process.

That's it for Vidar infostealer's in-depth static analysis and analysis automation! see you soon in another blogpost.

[here]:https://github.com/0x00-0x7F/IDAPython_scripts/blob/master/Vidar/deobfuscate_resolve_Vidar.py
[link-to-download-unpacked-exe]:https://bazaar.abuse.ch/sample/fca48ccbf3db60291b49f2290317b4919007dcc4fb943c1136eb70cf998260a5/
[link-to-part-1]:https://0x00-0x7f.github.io/A-Case-of-Vidar-Infostealer-Part-1-(-Unpacking-)/