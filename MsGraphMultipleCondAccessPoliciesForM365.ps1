Install-Module Microsoft.Graph
Import-Module Microsoft.Graph # Import the MsGraph modules

Select-MgProfile -Name "beta" # Selecting the Beta version of the MSGraph API. This is not neccesary if you want to run it using the official API

$permissions = @( # Define the permissions that You want to use during the connection with MsGraph (the scope)
    "Policy.Read.All",
    "Policy.ReadWrite.ConditionalAccess",
    "Application.Read.All"
)
Connect-MgGraph -Scopes $permissions

################################### Restrict non-admin users from creating tenants #####################################################
# This Setting is disabled by default. It is good to have it enabled               #####################################################
########################################################################################################################################

$authPolicy = Get-MgPolicyAuthorizationPolicy | Where-Object {$_.Id -eq "authorizationPolicy"}
if($authPolicy.DefaultUserRolePermissions.AllowedToCreateTenants){
    $params = @{ AllowedToCreateTenants = $false }
    Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions $params
}else{
    Write-Output "Users are not allowed to create Tenants"
}

##########################################################################################################################################
# You can create the country named location using the Microsoft Graph or the Admin Entra ID portal.
# Following code create the country named location "Approved Countries". In this case allowing US only.

$paramsNamedLocation = @{
"@odata.type" = "#microsoft.graph.countryNamedLocation"
DisplayName = "Approved Countries"
CountriesAndRegions = @("US")
IncludeUnknownCountriesAndRegions = $false
}

New-MgIdentityConditionalAccessNamedLocation -BodyParameter $paramsNamedLocation
$namedLocationId = (Get-MgIdentityConditionalAccessNamedLocation -Filter "DisplayName eq 'Approved Countries'").Id

############################## CA01:Require multifactor authentication for all users ##################################################
$conditions = @{
    Applications = @{
        includeApplications = 'All'
    };
    Users = @{
        includeUsers = 'All'
        excludeUsers = '11111111-1111-1111-1111-111111111111' # Use the User Object ID or the Group Object ID of the object that you want to exclude (User or Group)
    };
    ClientAppTypes = @('all')
}
$grantcontrols = @{
    BuiltInControls = @('mfa'); 
    Operator = 'OR'
}

$Params = @{
    DisplayName = "CA01:Require multifactor authentication for all users";
    State = "EnabledForReportingButNotEnforced"; # In this case I'm putting this policy in report only until I update the MFA Authentication Methods (Auth App and Fido Key Only)
    Conditions = $conditions;
    GrantControls =$grantcontrols;  
}
New-MgIdentityConditionalAccessPolicy @Params
########################################################################################################################################

##############################  CA02: Block access from other countries  ###############################################################
$conditions = @{
    Applications = @{
        includeApplications = 'All'
    };
    Users = @{
        includeUsers = 'All'
        excludeUsers = '11111111-1111-1111-1111-111111111111'
    };
    Locations = @{
        includeLocations = 'All'
        excludeLocations = $namedLocationId # This is the Object Id for your named location.
        # You can get that from Get-MgIdentityConditionalAccessNamedLocation or using the Microsoft Graph Explorer with the endpoint: identity/conditionalAccess/policies 
    };
    Devices = @{
        deviceFilter = @{
            mode = 'exclude'
            rule = 'device.isCompliant -eq True'
        }
    };
    ClientAppTypes = @('browser','mobileAppsAndDesktopClients')
}
$grantcontrols = @{
    BuiltInControls = @('block'); 
    Operator = 'OR'
}

$Params = @{
    DisplayName = "CA02: Block access from other countries";
    State = "enabled";
    Conditions = $conditions;
    GrantControls =$grantcontrols;  
}
New-MgIdentityConditionalAccessPolicy @Params
#################################################################################################################################################

############################################ CA03: Block Unapproved device types ################################################################
$conditions = @{
    Applications = @{
        includeApplications = 'All'
    };
    Users = @{
        includeUsers = 'All'
        excludeUsers = '11111111-1111-1111-1111-111111111111' # Use the User Object ID or the Group Object ID for the one that you want to exclude
    };
    Platforms = @{
        includePlatforms = @('windowsPhone','linux')
    };
    ClientAppTypes = @('all')
}
$grantcontrols = @{
    BuiltInControls = @('block'); 
    Operator = 'OR'
}

$Params = @{
    DisplayName = "CA03: Block Unapproved device types";
    State = "enabled";
    Conditions = $conditions;
    GrantControls =$grantcontrols;  
}
New-MgIdentityConditionalAccessPolicy @Params
#################################################################################################################################################

############################################ CA04: Disable Persistent Browser Session ################################################################
$conditions = @{
    Applications = @{
        includeApplications = 'All'
    };
    Users = @{
        includeUsers = 'All'
    };
    Platforms = @{
        includePlatforms = @('windowsPhone','linux')
    };
    ClientAppTypes = @('browser')
}
$sessionControls = @{
    persistentBrowser = @{
        mode = 'never'
        isEnabled = $true
    }
}

$Params = @{
    DisplayName = "CA04: Disable Persistent Browser Session";
    State = "enabled";
    Conditions = $conditions;
    SessionControls = $sessionControls
}

New-MgIdentityConditionalAccessPolicy @Params
#################################################################################################################################################

############################################ CA05: Require App Protection Policy ################################################################
$conditions = @{
    Applications = @{
        includeApplications = 'Office365'
    };
    Users = @{
        includeUsers = 'All'
    };
    Platforms = @{
        includePlatforms = @('android','iOS')
    };
    ClientAppTypes = @('browser','mobileAppsAndDesktopClients')
}
$grantcontrols = @{
    BuiltInControls = @('compliantApplication'); 
    Operator = 'OR'
}

$Params = @{
    DisplayName = "CA05: Require App Protection Policy";
    State = "enabled";
    Conditions = $conditions;
    GrantControls =$grantcontrols;  
}
New-MgIdentityConditionalAccessPolicy @Params
#################################################################################################################################################

############################################ CA06: Block legacy authentication ################################################################
$conditions = @{
    Applications = @{
        includeApplications = 'All'
    };
    Users = @{
        includeUsers = 'All'
        excludeUsers = '11111111-1111-1111-1111-111111111111' # Use the User Object ID or the Group Object ID for the one that you want to exclude. This is an array so you can put multiples Ids
    };
    ClientAppTypes = @('exchangeActiveSync','other')
}
$grantcontrols = @{
    BuiltInControls = @('block'); 
    Operator = 'OR'
}

$Params = @{
    DisplayName = "CA06: Block legacy authentication";
    State = "enabled";
    Conditions = $conditions;
    GrantControls =$grantcontrols;  
}
New-MgIdentityConditionalAccessPolicy @Params
#################################################################################################################################################

############################################ CA07: Require MFA to Join to Entra ID ################################################################
$conditions = @{
    Applications = @{
        includeUserActions = 'urn:user:registerdevice'
    };
    Users = @{
        includeUsers = 'All'
    };
    ClientAppTypes = @('all')
}
$grantcontrols = @{
    BuiltInControls = @('mfa'); 
    Operator = 'OR'
}

$Params = @{
    DisplayName = "CA07: Require MFA to Join to Entra ID";
    State = "enabled";
    Conditions = $conditions;
    GrantControls =$grantcontrols;  
}
New-MgIdentityConditionalAccessPolicy @Params
#################################################################################################################################################

############################################### CA08: Restrict access to Microsoft Admin Portals ###############################################
############  This condicional access needs to be managed very carefully. Exclude the Admin accounts from this policy ###########################
######## If for some reason something goes wrong then do not close the terminal. run the command Get-MgIdentityConditionalAccessPolicy       ####
# Get the Conditional policy Id for that particular policy and remove the policy with the command:                                           ####
#                    Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $ConditionalPolicyId                                ####
#################################################################################################################################################
$conditions = @{
    Applications = @{
        includeApplications = 'MicrosoftAdminPortals'
    };
    Users = @{
        includeUsers = 'All'
        excludeUsers = '11111111-1111-1111-1111-111111111111' # Use the User Object ID or the Group Object ID for the one that you want to exclude
    };
    ClientAppTypes = @('all')
}
$grantcontrols = @{
    BuiltInControls = @('block'); 
    Operator = 'OR'
}

$Params = @{
    DisplayName = "CA08: Restrict acecss to Microsoft Admin Portals";
    State = "enabled";
    Conditions = $conditions;
    GrantControls =$grantcontrols;  
}
New-MgIdentityConditionalAccessPolicy @Params

