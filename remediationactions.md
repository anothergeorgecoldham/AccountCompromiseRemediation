
## Account Remediation Actions
Below are the actions that must be completed on a specified EntraID account when the script is run.
This will be run if there is a suspicion of the account being breached.

Before we conduct any of these actions we must do a forensic investigation to understand what the user account had completed in the previous 7 days.  This is to be exported in structured data formats in a forensics folder.



Reset the user password
Revoke the user's refresh tokens
Enforce multi-factor authentication (if there are any exceptions for the user)
Remove new app passwords (for use with legacy authentication when using per-user MFA)
Remove added mailbox delegates
Remove changed mailbox folder permissions
Remove new automatic email forwarding
Remove untrusted (sideloaded) Outlook add-ins
Remove unknown entries in the Safe Senders list
Remove new external calendar sharing and publishing
Remove new or unknown synchronized mobile devices
Remove enterprise applications newly added via user-based consent
Remove new workflows in Power Automate
Remove newly created apps in Power Apps
Remove new sharing in Power Apps
Remove new sharing links in SharePoint and OneDrive
Remove guests newly added to Groups and Teams
For a compromised admin account, remove admin consent newly granted to enterprise applications
For a compromised admin account, remove client secrets newly added to app registrations
For a compromised Exchange admin account, remove modified journal rules, mail flow rules, and mailbox permission