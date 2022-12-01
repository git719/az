# Azure
Useful [Microsoft Azure Cloud](https://azure.microsoft.com/en-us/) code. 

## RBAC and MS Graph Management
These utilities can list RBAC and MS Graph object details, but are primarily examples of how to use the [Microsoft Authentication Library (MSAL) for Python](https://docs.microsoft.com/en-us/python/api/overview/azure/msal-python-overview?view=azure-python), especially the MSAL library Client Credential authentication flow. They are partly based on the following:

- <https://github.com/AzureAD/microsoft-authentication-library-for-python/blob/dev/sample/confidential_client_secret_sample.py>
- <https://gist.github.com/darrenjrobinson/8fb22f39aa65e9481c3fd3604ea1aa37>

The code can be used as basis for code that needs to: 

1. Use the Python MSAL library to acquire a token for a specific API, like MS Graph or Azure Resource Management

2. Then use that token to access that API


### Requirements
You must register a specific client app in your tenant and grant it the required permissions for the specific functions each utility requires. See <https://github.com/AzureAD/microsoft-authentication-library-for-python/wiki/Client-Credentials#registering-client-secrets-using-the-application-registration-portal> for how to do an app registration.

The scripts use a configuration directory at `$HOME/.<script_name>` to retrieve and store the required credentials, and also to store local cache files. The `credentials.yaml` file must be formated as follows: 

```
tenant_id:     UUID
client_idi:    UUID
client_secret: SECRET
```

If `credentials.yaml` file doesn't exist, an empty skeleton one will be created that you need to fill out accordingly.


### azls
This is an Azure RBAC and MS Graph listing utility.

This is the Python version. The GoLang version is at https://github.com/git719/zls. This version is a little slower, but the code can be useful for those working with Python. **Note**, this version is also usually behind in updates and may be fully rescinded and archived in the future in favor of the better GoLang version.


### aztag
A Proof-of-Concept script to test listing and updating of a Service Principal object's `tags` attribute. You have to know the SP's UUID. Usage: 

```
aztag Azure SP tagging utility v1.0
      UUID                        Display Service Principal (SP) tags attribute
      UUID "tag1,tag2"            Set SP tags to quoted, comma-delimited list
      [-i] UUID                   Use interactive Azure logon to display SP tags
      [-i] UUID "tag1,tag2"       Use interactive Azure logon to update SP tags
      -xt                         Delete cached accessTokens file
      -v                          Print this usage page
```


### azup
An RBAC role definition and assignment creator or updater.

```
azup Azure RBAC role definition & assignment creator/updater v123
     -d SPECFILE      Create or update role definition as per SPECFILE in JSON format
     -a SPECFILE      Create or update role assignment as per SPECFILE in YAML format
     -v               Display this usage
```

### azrm
An RBAC role definition and assignment remover.

```
azrm Azure RBAC role definition & assignment remover v121
     -d UUID|SPECFILE|"role name"      Delete role definition from Azure (SPECFILE in JSON format)
     -a UUID|SPECFILE                  Delete role assignment from Azure (SPECFILE in YAML format)
     -v                                Display this usage
```

### Group-Create
Script `Group-Create.ps1` is quick example of how to create an Azure AD group using `PowerShell` code.

### App-SP-Pair-Create 
Script `App-SP-Pair-Create.ps1` is a quick a dirty way of creating an App registration + Service Principal combo, and a password for the app. The benefit of this PowerShell version is that you can login interatively with a privileged account and create the pair. However this method also relies on delegation using Azure's built-in `Microsoft Graph PowerShell` with App ID 14d82eec-204b-4c2f-b7e8-296a70dab67e (Azure creates this app the first time a privileged user logs in an consents).

### azappsp
This is the Python equivalent of `App-SP-Pair-Create.ps1`: 

```
zure App/SP combo creation utility v21
  Usage: azappsp APP_SP_NAME
```
This version is non-interactive and therefore requires the registered app with necessary privileges that is mentioned above.

### azspauth
Reads and updates a Service Principal oAuth2PermissionGrants.

```
azspauth Azure SP MS Graph API permission lister/updater utility v1
         UUID                                Display Service Principal API permissions
         ID "space separated claims list"    Update oAuth2PermissionGrants ID with provided claims lis
```

