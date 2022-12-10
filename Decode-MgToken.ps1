# Decode-MgToken.ps1

$global:prgname         = "Decode-MgToken"
$global:prgver          = "1"

function die($msg) {
    Write-Host -ForegroundColor Yellow $msg ; Exit
}

function print_usage() {
    die("$prgname JWT token decoder v$prgver`n" +
        "    -tk `"TOKEN_STRING`"              Decode MSAL token string")
}

function dump_token($token) {
    # Validate as per https://tools.ietf.org/html/rfc7519. Access and ID tokens are fine, Refresh tokens will not work
    if ( !$token.Contains(".") -or !$token.StartsWith("eyJ") ) { 
        die "Invalid token. Does not start with 'eyJ' or contain any '.'"
    }

    # =============================================================================================
    # From https://github.com/TonyTromp/powershell-jwt-decoder/blob/main/decode-test.ps1
    $parts = $token.Split(".")
    for ($i=0; $i -lt 2; $i++) {
        $part = $parts[$i];
        $Stripped = $part.Replace('=','')  
        $ModulusValue = ($Stripped.length % 4)   
        switch ($ModulusValue) {
            '0' {$part = $Stripped}
            '1' {$part = $Stripped.Substring(0,$Stripped.Length - 1)}
            '2' {$part = $Stripped + ('=' * (4 - $ModulusValue))}
            '3' {$part = $Stripped + ('=' * (4 - $ModulusValue))}
        }
        [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($part)) | ConvertFrom-Json
    }
    exit 
}

if ( ($args.Count -lt 1) -or ($args.Count -gt 1) ) {
    print_usage  # Accept only one argument
}

dump_token $args[0]
