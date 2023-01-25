# Decode-JwtToken.ps1
# From https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
# and https://github.com/TonyTromp/powershell-jwt-decoder/blob/main/decode-test.ps1

$global:prgname         = "Decode-Token"
$global:prgver          = "0.3.1"

function die($msg) {
    Write-Host -ForegroundColor Yellow $msg ; Exit
}

function PrintUsage() {
    die("$prgname JWT token decoder v$prgver`n" +
        "    `"TOKEN_STRING`"              Decode MSAL token string")
}

function DecodeJwtToken($token) { 
    # Validate as per https://tools.ietf.org/html/rfc7519.
    # Access and ID tokens are fine, Refresh tokens will not work
    if ( !$token.Contains(".") -or !$token.StartsWith("eyJ") ) { 
        die "Invalid token. Does not start with 'eyJ' or contain any '.'"
    }
 
    # Header
    $tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')
    # Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenheader.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenheader += "=" }
    Write-Verbose "Base64 encoded (padded) header:"
    Write-Verbose $tokenheader
    # Convert from Base64 encoded string to PSObject all at once
    Write-Verbose "Decoded header:"
    [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json | fl | Out-Default
 
    # Payload
    $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    # Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
    Write-Verbose "Base64 encoded (padded) payoad:"
    Write-Verbose $tokenPayload
    # Convert to Byte array
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    # Convert to string array
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    Write-Verbose "Decoded array in JSON format:"
    Write-Verbose $tokenArray
    # Convert from JSON to PSObject
    $tokobj = $tokenArray | ConvertFrom-Json
    Write-Verbose "Decoded Payload:"
    
    return $tokobj
}

function DumpToken($token) {
    # Validate as per https://tools.ietf.org/html/rfc7519. Access and ID tokens are fine, Refresh tokens will not work
    if ( !$token.Contains(".") -or !$token.StartsWith("eyJ") ) { 
        die "Invalid token. Does not start with 'eyJ' or contain any '.'"
    }

    # From 
    $parts = $token.Split(".")
    for ($i=0; $i -lt 2; $i++) {
        $part = $parts[$i];
        #echo $part
        $Stripped = $part.Replace('=','')  
        $ModulusValue = ($Stripped.length % 4)   
        switch ($ModulusValue) {
            '0' {$part = $Stripped}
            '1' {$part = $Stripped.Substring(0,$Stripped.Length - 1)}
            '2' {$part = $Stripped + ('=' * (4 - $ModulusValue))}
            '3' {$part = $Stripped + ('=' * (4 - $ModulusValue))}
        }
        #[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($part)) | ConvertFrom-Json
        [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($part))
    }
}

if ( ($args.Count -lt 1) -or ($args.Count -gt 1) ) {
    PrintUsage  # Accept only one argument
}

#DumpToken $args[0]
DecodeJwtToken $args[0]
