. $PSScriptRoot\CommonServerPowerShell.ps1


$script:INTEGRATION_NAME = "EWS extension"
$script:COMMAND_PREFIX = "ews"
$script:INTEGRATION_ENTRY_CONTEX = "EWS"
$script:JUNK_RULE_ENTRY_CONTEXT = "$script:INTEGRATION_ENTRY_CONTEX.JunkRule(val.mailbox && val.mailbox == obj.mailbox)"

#### HELPER FUNCTIONS ####

function UpdateIntegrationContext([OAuth2DeviceCodeClient]$client){
    $integration_context = @{
        "DeviceCode" = $client.device_code
        "DeviceCodeExpiresIn" = $client.device_code_expires_in
        "DeviceCodeCreationTime" = $client.device_code_creation_time
        "AccessToken" = $client.access_token
        "RefreshToken" = $client.refresh_token
        "AccessTokenExpiresIn" = $client.access_token_expires_in
        "AccessTokenCreationTime" = $client.access_token_creation_time
    }

    $Demisto.setIntegrationContext($integration_context)
    <#
        .DESCRIPTION
        Update integration context from OAuth2DeviceCodeClient client

        .EXAMPLE
        UpdateIntegrationContext $client

        .PARAMETER search_name
        OAuth2DeviceCodeClient client.
    #>
}

function CreateNewSession {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope='Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope='Function')]
    param([string]$url, [string]$upn, [string]$password, [string]$bearer_token, [bool]$insecure, [bool]$proxy)

    $url = "$url/powershell-liveid?BasicAuthToOAuthConversion=true"

    if ($password){
        $credential = ConvertTo-SecureString "$password" -AsPlainText -Force
    } else {
        $credential = ConvertTo-SecureString "Bearer $bearer_token" -AsPlainText -Force
    }
    $credential = New-Object System.Management.Automation.PSCredential($upn, $credential)
    $session_option_params = @{
        "SkipCACheck" = $insecure
        "SkipCNCheck" = $insecure
    }
    $session_options =  New-PSSessionOption @session_option_params
    $sessions_params = @{
        "ConfigurationName" = "Microsoft.Exchange"
        "ConnectionUri" = $url
        "Credential" = $credential
        "Authentication" = "Basic"
        "AllowRedirection" = $true
        "SessionOption" = $session_options
    }
    $session = New-PSSession @sessions_params -WarningAction:SilentlyContinue

    if (!$session) {
        throw "Fail - establishing session to $url"
    }

    return $session
    <#
        .DESCRIPTION
        Creates new pssession using Oauth2.0 method.

        .PARAMETER uri
        Exchange Online uri.

        .PARAMETER upn
        User Principal Name (UPN) is the name of a system user in an email address format.

        .PARAMETER password
        Password is filled only if authentication method is basic auth.

        .PARAMETER bearer_token
        Valid bearer token value.

        .EXAMPLE proxy
        Wheter to user system proxy configuration or not.

        .PARAMETER insecure
        Wheter to trust any TLS/SSL Certificate) or not.


        .EXAMPLE
        CreateNewSession("outlook.com", "user@microsoft.com", "dfhsdkjhkjhvkdvbihsgiu")

        .OUTPUTS
        PSSession - PSSession object.

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession?view=powershell-7
    #>
}


function ParseJunkRulesToEntyContext([PSObject]$junk_rules_raw, [string]$mailbox){
    return @{
        $script:JUNK_RULE_ENTRY_CONTEXT = @{
            "Email" = $mailbox
            "MailboxOwnerId" = $junk_rules_raw.MailboxOwnerId
            "Identity" = $junk_rules_raw.Identity
            "BlockedSendersAndDomains" = $junk_rules_raw.BlockedSendersAndDomains
            "TrustedRecipientsAndDomains" = $junk_rules_raw.TrustedRecipientsAndDomains
            "TrustedSendersAndDomains" = $junk_rules_raw.TrustedSendersAndDomains
            "TrustedListsOnly" = $junk_rules_raw.TrustedListsOnly
            "ContactsTrusted" = $junk_rules_raw.ContactsTrusted
            "Enabled" = $junk_rules_raw.Enabled
        }
    }
}

#### OAUTH2.0 CLIENT - DEVICE CODE FLOW #####

class OAuth2DeviceCodeClient {
    [string]$application_id = "a0c73c16-a7e3-4564-9a95-2bdf47383716"
    [string]$application_scope = "offline_access%20https%3A//outlook.office365.com/.default"
    [string]$device_code
    [int]$device_code_expires_in
    [int]$device_code_creation_time
    [string]$access_token
    [string]$refresh_token
    [int]$access_token_expires_in
    [int]$access_token_creation_time
    [bool]$insecure
    [bool]$proxy

    OAuth2DeviceCodeClient([string]$device_code, [string]$device_code_expires_in, [string]$device_code_creation_time, [string]$access_token,
                            [string]$refresh_token,[string]$access_token_expires_in, [string]$access_token_creation_time, [bool]$insecure, [bool]$proxy) {
        $this.device_code = $device_code
        $this.device_code_expires_in = $device_code_expires_in
        $this.device_code_creation_time = $device_code_creation_time
        $this.access_token = $access_token
        $this.refresh_token = $refresh_token
        $this.access_token_expires_in = $access_token_expires_in
        $this.access_token_creation_time = $access_token_creation_time
        $this.insecure = $insecure
        $this.proxy = $proxy
        <#
            .DESCRIPTION
            OAuth2DeviceCodeClient manage state of OAuth2.0 device-code flow described in https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code.

            .DESCRIPTION
            Its not recomended to create an object using the constructor, Use static method CreateClientFromIntegrationContext() instead.

            OAuth2DeviceCodeClient states are:
                1. Getting device-code (Will be used in stage 2) and user-code (Will be used by the user to authorize permissions) from Microsoft application.
                2. Getting access-token and refresh-token - after use authorize (Using stage 1 - device code)
                3. Refresh access-token if access-token is expired.

            .PARAMETER device_code
            A long string used to verify the session between the client and the authorization server.
            The client uses this parameter to request the access token from the authorization server.

            .PARAMETER device_code_expires_in
            The number of seconds before the device_code and user_code expire. (15 minutes)

            .PARAMETER access_token
            Opaque string, Issued for the scopes that were requested.

            .PARAMETER refresh_token
            Opaque string, Issued if the original scope parameter included offline_access. (Valid for 90 days)

            .PARAMETER access_token_expires_in
            Number of seconds before the included access token is valid for. (Usally - 60 minutes)

            .PARAMETER access_token_creation_time
            Unix time of access token creation (Used for knowing when to refresh the token).

            .PARAMETER access_token_expires_in
            Number of seconds before the included access token is valid for. (Usally - 60 minutes)

            .PARAMETER insecure
            Wheter to trust any TLS/SSL Certificate) or not.

            .PARAMETER proxy
            Wheter to user system proxy configuration or not.

            .NOTES
            1. Application id - a0c73c16-a7e3-4564-9a95-2bdf47383716 , This is well-known application publicly managed by Microsoft and will not work in on-premise enviorment.

            .LINK
            https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
        #>
    }

    static [OAuth2DeviceCodeClient]CreateClientFromIntegrationContext([bool]$insecure, [bool]$proxy){
        $ic = $script:Demisto.getIntegrationContext()
        $client = [OAuth2DeviceCodeClient]::new($ic.DeviceCode, $ic.DeviceCodeExpiresIn, $ic.DeviceCodeCreationTime, $ic.AccessToken, $ic.RefreshToken,
                                                $ic.AccessTokenExpiresIn, $ic.AccessTokenCreationTime, $insecure, $proxy)

        return $client
        <#
            .DESCRIPTION
            Static method which create object (factory method) from populated values in integration context.

            .EXAMPLE
            [OAuth2DeviceCodeClient]::CreateClientFromIntegrationContext()

            .OUTPUTS
            OAuth2DeviceCodeClient initialized object.
        #>
    }

    [PSObject]AuthorizationRequest() {
        # Reset object-properties
        $this.device_code = $null
        $this.device_code_expires_in = $null
        $this.device_code_creation_time = $null
        # Get device-code and user-code
        $params = @{
            "URI" = "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"
            "Method" = "Post"
            "Headers" = (New-Object "System.Collections.Generic.Dictionary[[String],[String]]").Add("Content-Type", "application/x-www-form-urlencoded")
            "Body" = "client_id=$($this.application_id)&scope=$($this.application_scope)"
            "NoProxy" = !$this.proxy
            "SkipCertificateCheck" = $this.insecure
        }
        $response = Invoke-WebRequest @params
        $response_body = ConvertFrom-Json $response.Content
        # Update object properties
        $this.device_code = $response_body.device_code
        $this.device_code_creation_time = [int][double]::Parse((Get-Date -UFormat %s))
        $this.device_code_expires_in = [int]::Parse($response_body.expires_in)

        return $response_body

        <#
            .DESCRIPTION
            Reset values populated in instance context and getting new device-code and user-code.

            .EXAMPLE
            $client.AuthorizationRequest()

            .OUTPUTS
            psobject - Raw body response.

            .LINK
            https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code#device-authorization-request
        #>
    }

    [psobject]AccessTokenRequest() {
        # Get new token using device-code
        try {
            $params = @{
                "URI" = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
                "Method" = "Post"
                "Headers" = (New-Object "System.Collections.Generic.Dictionary[[String],[String]]").Add("Content-Type", "application/x-www-form-urlencoded")
                "Body" = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&code=$($this.device_code)&client_id=$($this.application_id)"
                "NoProxy" = !$this.proxy
                "SkipCertificateCheck" = $this.insecure
            }
            $response = Invoke-WebRequest @params
            $response_body = ConvertFrom-Json $response.Content
        }
        catch {
            $response_body = ConvertFrom-Json $_.ErrorDetails.Message
            if ($response_body.error -eq "authorization_pending" -or $response_body.error -eq "invalid_grant") {
                $error_details = "Please run command !ews-start-auth , before running this command."
            }
            elseif ($response_body.error -eq "expired_token") {
                $error_details = "At least $($this.access_token_expires_in) seconds have passed from executing !ews-start-auth, Please run the ***ews-start-auth*** command again."
            } else {
                $error_details = $response_body
            }

            throw "Unable to get access token for your account, $error_details"
        }
        # Update object properties
        $this.access_token = $response_body.access_token
        $this.refresh_token = $response_body.refresh_token
        $this.access_token_expires_in = [int]::Parse($response_body.expires_in)
        $this.access_token_creation_time = [int][double]::Parse((Get-Date -UFormat %s))

        return $response_body

        <#
            .DESCRIPTION
            Getting access-token and refresh-token from Microsoft application based on the device-code we go from AuthorizationRequest() method.

            .EXAMPLE
            $client.AccessTokenRequest()

            .OUTPUTS
            psobject - Raw body response.

            .LINK
            https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code#authenticating-the-user
        #>
    }

    [psobject]RefreshTokenRequest() {
        # Get new token using refresh token
        try {
            $params = @{
                "URI" = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
                "Method" = "Post"
                "Headers" = (New-Object "System.Collections.Generic.Dictionary[[String],[String]]").Add("Content-Type", "application/x-www-form-urlencoded")
                "Body" = "grant_type=refresh_token&client_id=$($this.application_id)&refresh_token=$($this.refresh_token)&scope=$($this.application_scope)"
                "NoProxy" = !$this.proxy
                "SkipCertificateCheck" = $this.insecure
            }
            $response = Invoke-WebRequest @params
            $response_body = ConvertFrom-Json $response.Content
        }
        catch {
            $response_body = ConvertFrom-Json $_.ErrorDetails.Message
            if ($response_body.error -eq "invalid_grant") {
                $error_details = "Please login to grant account permissions (After 90 days grant is expired) !ews-start-auth."
            }
            else {
                $error_details = $response_body
            }

            throw "Unable to refresh access token for your account, $error_details"
        }
        # Update object properties
        $this.access_token = $response_body.access_token
        $this.refresh_token = $response_body.refresh_token
        $this.access_token_expires_in = [int]::Parse($response_body.expires_in)
        $this.access_token_creation_time = [int][double]::Parse((Get-Date -UFormat %s))

        return $response_body

        <#
            .DESCRIPTION
            Getting new access-token and refresh-token from Microsoft application based on the refresh-token we got from AccessTokenRequest() method.

            .EXAMPLE
            $client.RefreshTokenRequest()

            .OUTPUTS
            PSObject - Raw body response.

            .LINK
            https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-implicit-grant-flow#refreshing-tokens
        #>
    }

    [bool]IsDeviceCodeExpired(){
        if (!$this.device_code){
            return $true
        }
        $current_time = [int][double]::Parse((Get-Date -UFormat %s)) - 30
        $valid_until = $this.device_code_creation_time + $this.access_token_expires_in

        return $current_time -gt $valid_until

        <#
            .DESCRIPTION
            Check if device-code expired.

            .EXAMPLE
            $client.IsDeviceCodeExpired()

            .OUTPUTS
            bool - True If device-code expired else False.

            .LINK
            https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-configurable-token-lifetimes#configurable-token-lifetime-properties-after-the-retirement
        #>
    }

    [bool]IsAccessTokenExpired(){
        if (!$this.access_token){
            return $true
        }
        $current_time = [int][double]::Parse((Get-Date -UFormat %s)) - 30
        $valid_until = $this.access_token_creation_time + $this.access_token_expires_in

        return $current_time -gt $valid_until
        <#
            .DESCRIPTION
            Check if access-token expired.

            .EXAMPLE
            $client.IsAccessTokenExpired()

            .OUTPUTS
            bool - True If access-token expired else False.

            .LINK
            https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-configurable-token-lifetimes#configurable-token-lifetime-properties-after-the-retirement
        #>
    }

    RefreshTokenIfExpired(){
        if ($this.access_token -and $this.IsAccessTokenExpired()) {
            $this.RefreshTokenRequest()
        }
        <#
            .DESCRIPTION
            Refresh access token if expired, with offset of 30 seconds.

            .EXAMPLE
            $client.RefreshTokenIfExpired()
        #>
    }
}

#### Security And Compliance client - OAUTH2.0 ####

class ExchangeOnlineClient {
    [string]$url
    [string]$upn
    [string]$password
    [string]$bearer_token
    [psobject]$session
    [bool]$insecure
    [bool]$proxy

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope='Function')]
    ExchangeOnlineClient([string]$url, [string]$upn, [string]$password, [string]$bearer_token, [bool]$insecure, [bool]$proxy) {
        $this.upn = $upn
        $this.password = $password
        $this.bearer_token = $bearer_token
        $this.insecure = $insecure
        $this.proxy = $proxy
        $this.url = $url
        <#
            .DESCRIPTION
            ExchangeOnlineClient connect to Exchange Online using powershell session (OAuth2.0) and allow interact with it.

            .PARAMETER uri
            Exchange online url.

            .PARAMETER upn
            User Principal Name (UPN) is the name of a system user in an email address format.

            .PARAMETER password
            Password is filled only if authentication method is basic auth.

            .PARAMETER bearer_token
            Valid bearer token value.

            .PARAMETER insecure
            Wheter to trust any TLS/SSL Certificate) or not.

            .EXAMPLE proxy
            Wheter to user system proxy configuration or not.

            .EXAMPLE
            $exo_client = [ExchangeOnlineClient]::new("outlook.com", "user@microsoft.com", "dfhsdkjhkjhvkdvbihsgiu")
        #>
    }

    CreateSession() {
        $this.session = CreateNewSession -url $this.url -upn $this.upn -password $this.password -bearer_token $this.bearer_token -insecure $this.insecure -proxy $this.proxy
        <#
            .DESCRIPTION
            This method is for internal use. It creates session to Exchange Online.

            .EXAMPLE
            $client.CreateSession()

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession?view=powershell-7
            https://docs.microsoft.com/en-us/powershell/partnercenter/multi-factor-auth?view=partnercenterps-3.0#exchange-online-powershell
        #>
    }

    CloseSession() {
        if ($this.session) {
            Remove-PSSession $this.session
        }
        <#
            .DESCRIPTION
            This method is for internal use. It creates session to Exchange Online.

            .EXAMPLE
            $client.CloseSession()

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/remove-pssession?view=powershell-7
            https://docs.microsoft.com/en-us/powershell/partnercenter/multi-factor-auth?view=partnercenterps-3.0#exchange-online-powershell
        #>
    }

    [psobject]GetJunkRules([string]$mailbox) {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Get-MailboxJunkEmailConfiguration -AllowClobber
            $cmd_params = @{
                "Identity" = $mailbox
            }
            $response = Get-MailboxJunkEmailConfiguration @cmd_params

            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
        <#
            .DESCRIPTION
            Create compliance search in the Exchange Online.

            .PARAMETER mailbox
            The name of the compliance search.

            .EXAMPLE
            $client.NewSearch("new-search")
            $client.NewSearch("new-search", "new-search-description")

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/new-compliancesearch?view=exchange-ps
        #>
    }

    SetJunkRules([string]$mailbox, [string[]]$add_blocked_senders_and_domains, [string[]]$remove_blocked_senders_and_domains,
                 [string[]]$add_trusted_senders_and_domains, [string[]]$remove_trusted_senders_and_domains,
                 [bool]$trusted_lists_only, [bool]$contacts_trusted, [bool]$enabled) {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Set-MailboxJunkEmailConfiguration -AllowClobber
            $cmd_params = @{
                "Identity" = $mailbox
                "BlockedSendersAndDomains" = @{Add = $add_blocked_senders_and_domains
                                               Remove = $remove_blocked_senders_and_domains}
                "TrustedSendersAndDomains" =  @{Add = $add_trusted_senders_and_domains
                                                Remove = $remove_trusted_senders_and_domains}
                "TrustedListsOnly" = $trusted_lists_only
                "ContactsTrusted" = $contacts_trusted
                "Enabled" = $enabled
                "Confirm" = $false
            }
            Set-MailboxJunkEmailConfiguration @cmd_params
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
        <#
            .DESCRIPTION
            Create compliance search in the Exchange Online.

            .PARAMETER mailbox
            The name of the compliance search.

            .EXAMPLE
            $client.NewSearch("new-search")
            $client.NewSearch("new-search", "new-search-description")

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/new-compliancesearch?view=exchange-ps
        #>
    }

    SetGlobalJunkRules([string]$mailbox, [string[]]$add_blocked_senders_and_domains, [string[]]$remove_blocked_senders_and_domains,
                       [string[]]$add_trusted_senders_and_domains, [string[]]$remove_trusted_senders_and_domains,
                       [bool]$trusted_lists_only, [bool]$contacts_trusted, [bool]$enabled) {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Set-MailboxJunkEmailConfiguration -AllowClobber
            Import-PSSession -Session $this.session -CommandName Get-Mailbox -AllowClobber
            $cmd_params = @{
                "BlockedSendersAndDomains" = @{Add = $add_blocked_senders_and_domains
                                               Remove = $remove_blocked_senders_and_domains}
                "TrustedSendersAndDomains" =  @{Add = $add_trusted_senders_and_domains
                                                Remove = $remove_trusted_senders_and_domains}
                "TrustedListsOnly" = $trusted_lists_only
                "ContactsTrusted" = $contacts_trusted
                "Enabled" = $enabled
                "Confirm" = $false
            }
            Get-Mailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited | foreach {
                Set-MailboxJunkEmailConfiguration -Identity $_.Name @cmd_params
            }
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
        <#
            .DESCRIPTION
            Create compliance search in the Exchange Online.

            .PARAMETER mailbox
            The name of the compliance search.

            .EXAMPLE
            $client.NewSearch("new-search")
            $client.NewSearch("new-search", "new-search-description")

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/new-compliancesearch?view=exchange-ps
        #>
    }

   [PSObject]GetMessageTrace([string[]]$sender_address, [string[]]$recipient_address,[string[]]$from_ip, [string[]]$to_ip, [string[]]$message_id,
                             [Guid]$message_trace_id, [int32]$page, [int32]$page_size, [DateTime]$start_date, [DateTime]$end_date) {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Get-MessageTrace -AllowClobber
            $cmd_params = @{
                "SenderAddress" = $sender_address
                "RecipientAddress" = $recipient_address
                "FromIP" = $from_ip
                "ToIP" = $to_ip
                "MessageId" = $message_id
                "MessageTraceId" = $message_trace_id
                "Page" = $page
                "PageSize" = $page_size
                "StartDate" = $start_date
                "EndDate" = $end_date
            }
            $response = Get-MessageTrace @cmd_params

            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
        <#
            .DESCRIPTION
            Create compliance search in the Exchange Online.

            .PARAMETER mailbox
            The name of the compliance search.

            .EXAMPLE
            $client.NewSearch("new-search")
            $client.NewSearch("new-search", "new-search-description")

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/new-compliancesearch?view=exchange-ps
        #>
    }
}

#### COMMAND FUNCTIONS ####

function TestModuleCommand ([OAuth2DeviceCodeClient]$oclient, [ExchangeOnlineClient]$exo_client) {
    if ($exo_client.password) {
        $exo_client.ListSearchActions() | Out-Null
    }
    else {
        throw "Fill password for basic auth or use command !o365-sc-auth-start for Oauth2.0 authorization (MFA enabled accounts)."
    }
    $raw_response = $null
    $human_readable = "ok"
    $entry_context = $null

    return $human_readable, $entry_context, $raw_response
}

function StartAuthCommand ([OAuth2DeviceCodeClient]$client) {
    $raw_response = $client.AuthorizationRequest()
    $human_readable = "## $script:INTEGRATION_NAME - Authorize instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin) and enter the code **$($raw_response.user_code)** to authenticate.
2. Run the following command **!$script:COMMAND_PREFIX-auth-complete** in the War Room."
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function CompleteAuthCommand ([OAuth2DeviceCodeClient]$client) {
    $raw_response = $client.AccessTokenRequest()
    $human_readable = "Your account **successfully** authorized!"
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function TestAuthCommand ([OAuth2DeviceCodeClient]$oclient, [ExchangeOnlineClient]$exo_client) {
    $raw_response = $oclient.RefreshTokenRequest()
    $human_readable = "**Test ok!**"
    $entry_context = @{}
    try {
        $exo_client.CreateSession()
    }
    finally {
        $exo_client.CloseSession()
    }

    return $human_readable, $entry_context, $raw_response
}

function GetJunkRulesCommand([ExchangeOnlineClient]$client, [hashtable]$kwargs) {
    $raw_response = $client.GetJunkRules($kwargs.mailbox)
    $md_columns = $raw_response | Select-Object -Property BlockedSendersAndDomains, TrustedSendersAndDomains, ContactsTrusted, TrustedListsOnly, Enabled
    $human_readable = TableToMarkdown $md_columns  "$script:INTEGRATION_NAME - '$($kwargs.mailbox)' Junk rules"
    $entry_context = ParseJunkRulesToEntyContext $raw_response $kwargs.mailbox

    return $human_readable, $entry_context, $raw_response
}

function SetJunkRulesCommand([ExchangeOnlineClient]$client, [hashtable]$kwargs) {
    $add_blocked_senders_and_domains = ArgToList $kwargs.add_blocked_senders_and_domains
    $remove_blocked_senders_and_domains = ArgToList $kwargs.remove_blocked_senders_and_domains
    $add_trusted_senders_and_domains = ArgToList $kwargs.add_trusted_senders_and_domains
    $remove_trusted_senders_and_domains = ArgToList $kwargs.remove_trusted_senders_and_domains
    if ($kwargs.trusted_lists_only) {
        $trusted_lists_only = ConvertTo-Boolean $kwargs.trusted_lists_only
    }
    if ($kwargs.contacts_trusted) {
        $contacts_trusted = ConvertTo-Boolean $kwargs.contacts_trusted
    }
    if ($kwargs.enabled) {
        $kwargs.enabled= ConvertTo-Boolean $kwargs.enabled
    }
    $client.SetJunkRules($kwargs.mailbox, $add_blocked_senders_and_domains, $remove_blocked_senders_and_domains,
                         $add_trusted_senders_and_domains, $remove_trusted_senders_and_domains,
                         $trusted_lists_only, $contacts_trusted, $enabled)
    $raw_response = @{}
    $human_readable = "$script:INTEGRATION_NAME - '$($kwargs.mailbox)' Junk rules **modified**!"
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function SetGlobalJunkRulesCommand([ExchangeOnlineClient]$client, [hashtable]$kwargs) {
    $add_blocked_senders_and_domains = ArgToList $kwargs.add_blocked_senders_and_domains
    $remove_blocked_senders_and_domains = ArgToList $kwargs.remove_blocked_senders_and_domains
    $add_trusted_senders_and_domains = ArgToList $kwargs.add_trusted_senders_and_domains
    $remove_trusted_senders_and_domains = ArgToList $kwargs.remove_trusted_senders_and_domains
    if ($kwargs.trusted_lists_only) {
        $trusted_lists_only = ConvertTo-Boolean $kwargs.trusted_lists_only
    }
    if ($kwargs.contacts_trusted) {
        $contacts_trusted = ConvertTo-Boolean $kwargs.contacts_trusted
    }
    if ($kwargs.enabled) {
        $kwargs.enabled= ConvertTo-Boolean $kwargs.enabled
    }
    $client.SetGlobalJunkRules($kwargs.mailbox, $add_blocked_senders_and_domains, $remove_blocked_senders_and_domains,
                               $add_trusted_senders_and_domains, $remove_trusted_senders_and_domains,
                               $trusted_lists_only, $contacts_trusted, $enabled)
    $raw_response = @{}
    $human_readable = "$script:INTEGRATION_NAME - Junk rules globally **modified**!"
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function GetMessageTraceCommand([ExchangeOnlineClient]$client, [hashtable]$kwargs) {
    $sender_address = ArgToList $kwargs.sender_address
    $recipient_address = ArgToList $kwargs.recipient_address
    $from_ip = ArgToList $kwargs.from_ip
    $to_ip = ArgToList $kwargs.to_ip
    $message_id = ArgToList $kwargs.message_id

    $raw_response = $client.GetMessageTrace($sender_address, $sender_address, $recipient_address,
                                            $from_ip, $to_ip, $message_id, $kwargs.message_trace_id,
                                            $kwargs.page, $kwargs.page_size, $kwargs.start_date, $kwargs.end_date,
                                            $kwargs.message_trace_id, $kwargs.page, $kwargs.page_size, $kwargs.start_date,
                                            $kwargs.end_date)
#    $md_columns = $raw_response | Select-Object -Property BlockedSendersAndDomains, TrustedSendersAndDomains, ContactsTrusted, TrustedListsOnly, Enabled
#    $human_readable = TableToMarkdown $md_columns  "$script:INTEGRATION_NAME - '$($kwargs.mailbox)' Junk rules"
    $human_readable = "Here"
    $entry_context = ""

    return $human_readable, $entry_context, $raw_response
}

#### INTEGRATION COMMANDS MANAGER ####

function Main {
    $command = $Demisto.GetCommand()
    $command_arguments = $Demisto.Args()
    $integration_params = $Demisto.Params()
    <#
        Proxy currently isn't supported by PWSH New-Pssession, However partly implmentation of proxy feature still function (OAuth2.0 and redirect),
        leaving this parameter for feature development if required.
    #>
    $no_proxy = $false
    $insecure = (ConvertTo-Boolean $integration_params.insecure)

    try {
        # Creating Compliance and search client
        $oauth2_client = [OAuth2DeviceCodeClient]::CreateClientFromIntegrationContext($insecure, $no_proxy)
        # Refreshing tokens if expired
        $oauth2_client.RefreshTokenIfExpired()
        # Creating ExchangeOnline client
        $exo_client = [ExchangeOnlineClient]::new($integration_params.url, $integration_params.credentials.identifier,
                                                        $integration_params.credentials.password, $oauth2_client.access_token, $insecure, $no_proxy)
        # Executing command
        $Demisto.Debug("Command being called is $Command")
        switch ($command) {
            "test-module" {
                ($human_readable, $entry_context, $raw_response) = TestModuleCommand $oauth2_client $exo_client
            }
            "$script:COMMAND_PREFIX-auth-start" {
                ($human_readable, $entry_context, $raw_response) = StartAuthCommand $oauth2_client
            }
            "$script:COMMAND_PREFIX-auth-complete" {
                ($human_readable, $entry_context, $raw_response) = CompleteAuthCommand $oauth2_client
            }
            "$script:COMMAND_PREFIX-auth-test" {
                ($human_readable, $entry_context, $raw_response) = TestAuthCommand $oauth2_client $exo_client
            }
            "$script:COMMAND_PREFIX-junk-rules-get" {
                ($human_readable, $entry_context, $raw_response) = GetJunkRulesCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-junk-rules-set" {
                ($human_readable, $entry_context, $raw_response) = SetJunkRulesCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-global-junk-rules-set" {
                ($human_readable, $entry_context, $raw_response) = SetGlobalJunkRulesCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-message-trace-get" {
                ($human_readable, $entry_context, $raw_response) = GetMessageTraceCommand $exo_client $command_arguments
            }
        }
        # Updating integration context if access token changed
        UpdateIntegrationContext $oauth2_client
        # Return results to Demisto Server
        ReturnOutputs $human_readable $entry_context $raw_response | Out-Null
    }
    catch {
        $Demisto.debug("Integration: $script:INTEGRATION_NAME
Command: $command
Arguments: $($command_arguments | ConvertTo-Json)
Error: $($_.Exception.Message)")
        if ($command -ne "test-module") {
            ReturnError "Error:
            Integration: $script:INTEGRATION_NAME
            Command: $command
            Arguments: $($command_arguments | ConvertTo-Json)
            Error: $($_.Exception)" | Out-Null
        }
        else {
            ReturnError $_.Exception.Message
        }
    }
}

# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT $Test) {
    Main
}
