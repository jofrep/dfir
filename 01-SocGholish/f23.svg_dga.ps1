
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
    #Write-Host $domain ;
}

