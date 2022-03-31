---
layout: post
title:  "A Case of Vidar Infostealer - Part 1 (Unpacking)"
date:   2022-03-27
categories: Infostealers
---

Hi, in this post, I'll be unpacking and analyzing Vidar infostealer from my <b>BSides Islamabad 2021</b> talk. Initial stage sample comes as .xll file which is Excel Add-in file extension. It allows third party applications to add extra functionality to Excel using Excel-DNA, a tool or library that is used to write .NET Excel add-ins. In this case, xll file embeds malicious downloader dll which further drops packed Vidar infostealer executable on victim machine, investigating whole infection chain is out of scope for this post, however I'll be digging deep the dropped executable (Packed Vidar) in Part1 of this blogpost and final infostealer payload in Part2. 


<b>SHA256:</b> [5cd0759c1e566b6e74ef3f29a49a34a08ded2dc44408fccd41b5a9845573a34c][link-to-download-packed-exe]


<STRONG>Technical Analysis</STRONG>


I usually start unpacking general malware packers/loaders by looking it first into basic static analysis tools, then opening it into IDA and taking a bird's eye view of different sections for variables with possible encrypted strings, keys, imports or other global variables containing important information, checking if it has any crypto signatures identified and then start debugging it. After loading it into x64dbg, I first put breakpoint on memory allocation APIs such as LocalAlloc, GlobalAlloc, VirtualAlloc and memory protection API: VirtualProtect, and hit run button to see if any of the breakpoints hits. If yes, then it is fairly simple to unpack it and extract next stage payload, otherwise it might require in-depth static and dynamic analysis. Let's hit run button to see where it takes us next.


<Strong>Shellcode Extraction</Strong>


Here we go, the first breakpoint hits in this case, is <b>VirtualProtect</b>, being called on a <b>stack</b> memory region of size <b>0x28A</b> to grant it <b>E</b>xecute <b>R</b>ead <b>W</b>rite (0x40) protection, strange enough right!

![image](/assets/images/vidar_packed/virtualprotect.png){:class="img-responsive"}
*Figure1*

first few opcodes <b>E9</b>, <b>55</b>, <b>8B</b> in dumped data on stack correspond to <b>jmp</b>, <b>push</b> and <b>mov</b> instructions respectively, so it can be assumed it is shellcode being pushed on stack and then granted Execute protection to later execute it, If I hit execute till return button on VirtualProtect and trace back from it into disassembler, I can see shellcode stored as <b>stack strings</b> right before VirtualProtect call and list of arguments are pushed as shown in the figure below

![image](/assets/images/vidar_packed/shellcode_stack_strings.png){:class="img-responsive"}


following few statements are preparing to execute shellcode on stack by retrieving a handle to a device context (DC) object and passing this handle to GrayStringA to execute shellcode from stack (ptr value in eax taken from Figure1)


![image](/assets/images/vidar_packed/shellcode_exec.png){:class="img-responsive"}


let's now start exploring the shellcode.

<Strong>Debugging shellcode to extract final payload</Strong>

As soon as, <b>GrayStringA</b> executes, it hits on <b>VirtualAlloc</b> breakpoint set in the debugger, which is being called to reserver/commit 0xAA3CE size of memory with <b>MEM_COMMIT \| MEM_RESERVE</b> (0x3000) memory allocation type

![image](/assets/images/vidar_packed/virtualalloc_.png){:class="img-responsive"}


returning control from <b>VirtualAlloc</b> and stepping over one more time from ret, leads us to the shellcode, next few statements after VirtualAlloc call are pushing pointer to newly created buffer, size of the buffer and the file handle for currently loaded process on stack to call <b>ReadFile</b> 

![image](/assets/images/vidar_packed/readfile_handle.png){:class="img-responsive"}

which reads 0xAA3CE bytes of data from parent process image into the buffer, let's say it <b>buffer1</b>

![image](/assets/images/vidar_packed/buffer1.png){:class="img-responsive"}


further execution again hits at <b>VirtualAlloc</b> breakpoint, this time allocating <b>0x14F0</b> bytes of memory, I'll now put a write breakpoint in the memory region reserved/committed by second VirtualAlloc API call to see what and how data gets dumped into second buffer, <b>buffer2</b>. Hitting Run button once more will break at instruction shown in the figure below

![image](/assets/images/vidar_packed/copy_loop.png){:class="img-responsive"}

this loop is copying 0x14F0 bytes of data from a certain offset of buffer1 into buffer2, next few statements are agaian calling VirtualAlloc to allocate another 0x350DE bytes of memory say <b>buffer3</b>, pushing returned buffer address along with an offset from buffer1 on stack to copy 0x350DE bytes of data from buffer1 into buffer3

![image](/assets/images/vidar_packed/buffer3_.png){:class="img-responsive"}


loop in the following figure is decrypting data copied to buffer2, next push instruction is pushing the buffer3 pointer on stack as an argument of the routine being called from buffer2 address in edx which is supposed to process buffer3 contents

![image](/assets/images/vidar_packed/decrypt_buffer2.png){:class="img-responsive"}

figure below is showing final buffer2 decrypted contents 

![image](/assets/images/vidar_packed/encrypted_buffer2_.png){:class="img-responsive"}

stepping into <b>edx</b> starts executing buffer2 contents, where it seems to push stack strings for kernel32.dll first and then retrieves kernel32.dll handle by parsing PEB (Process Environment Block) structure 

![image](/assets/images/vidar_packed/PEB_parsing.png){:class="img-responsive"}

retrieved kernel32.dll handle is passed to next call along with another argument with constant <b>FF7F721A</b> value, a quick Google search for this constant results in some public sandbox links but not clear what is this exactly about. Let's dig into it further, stepping over this routine <b>0x0A4E</b> results in <b>GetModuleFileNameW</b> API's resolved address from Kernel32.dll stored in eax which means this routine is meant to resolve hashed APIs

![image](/assets/images/vidar_packed/resolved.png){:class="img-responsive"}

similarly second call resolves <b>7F91A078</b> hash value to <b>ExitProcess</b> API, wrapper routine <b>0x0A4E</b> iterates over library exports and routine <b>0x097A</b> is computing hash against input export name parameter. Shellcode seems to be using a custom algorithm to hash API, computed hash value is retuned back into <b>eax</b> which is compared to the input hash value stored at [ebp-4], if both hash values are equal, API is resolved and its address is stored in eax

![image](/assets/images/vidar_packed/api_hash_resolve.png){:class="img-responsive"}

next few instructions write some junk data on stack followed by pushing pointer to buffer3 and total size of buffer3 contents (0x350C0) on stack and execute routine <b>0x0BE9</b> for decryption - this custom decryption scheme works by processing each byte from buffer3 using repetitive neg, sub, add, sar, shl, not, or and xor set of instructions with hard-coded values in multiple layers, intermediate result is stored in [ebp-1] 

![image](/assets/images/vidar_packed/routine_decrypt_buffer3.png){:class="img-responsive"}

and final value overwrites the corresponding buffer3 value at [eax] offset

![image](/assets/images/vidar_packed/buffer3_contents_in_decryption.png){:class="img-responsive"}

once buffer3 contents are decrypted, it continues to resolve other important APIs in next routine <b>0x0FB6</b>

![image](/assets/images/vidar_packed/more_api_hashes.png){:class="img-responsive"}

I wrote a simple POC python script for hashing algorithm implemented by decrypted shellcode which can be found [here][here]

![image](/assets/images/vidar_packed/poc_hashing_algorithm.png){:class="img-responsive"}

after all required APIs have been resolved, it proceeds to create a new process

![image](/assets/images/vidar_packed/createProcess.png){:class="img-responsive"} 

using <b>CreateProcessW</b> in suspended mode

![image](/assets/images/vidar_packed/process_created_in_suspended_mode.png){:class="img-responsive"}

and then final payload is injected into newly created process using SetThreadContext API, <b>CONTEXT</b> structure for remote thread is set up with ContextFlag and required memory buffers and <b>SetThreadContext</b> API is called with current thread handle and remote thread CONTEXT structure for code injection

![image](/assets/images/vidar_packed/final_injected_payload.png){:class="img-responsive"}

main process terminates right after launching this process, we can now take a dump of this process to extract final payload.

That's it for unpacking! see you soon in the next blogpost covering detailed analysis of Vidar infostealer.

[here]:https://github.com/0x00-0x7F/RE_tips_and_tricks/blob/master/vidar_packer/api_hash_strings.py
[link-to-download-packed-exe]:https://bazaar.abuse.ch/sample/5cd0759c1e566b6e74ef3f29a49a34a08ded2dc44408fccd41b5a9845573a34c/