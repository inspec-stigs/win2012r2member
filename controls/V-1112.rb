# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1112 - Outdated or unused accounts must be removed from the system or disabled.'
control 'V-1112' do
  impact 0.1
  title 'Outdated or unused accounts must be removed from the system or disabled.'
  desc 'Outdated or unused accounts provide penetration points that may go undetected.  Inactive accounts must be deleted if no longer necessary or, if still required, disabled until needed.'
  tag 'stig', 'V-1112'
  tag severity: 'low'
  tag checkid: 'C-69285r1_chk'
  tag fixid: 'F-45780r1_fix'
  tag version: 'WN12-GE-000014'
  tag ruleid: 'SV-52854r3_rule'
  tag fixtext: 'Regularly review accounts to determine if they are still active.  Remove or disable accounts that have not been used in the last 35 days.'
  tag checktext: 'Run "PowerShell".

Member servers and standalone systems:
Copy or enter the lines below to the PowerShell window and enter. (Entering twice may be required. Do not include the quotes at the beginning and end of the query.)

"([ADSI](WinNT://{0} -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq user } | ForEach {
 $user = ([ADSI]$_.Path)
 $lastLogin = $user.Properties.LastLogin.Value
 $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
 if ($lastLogin -eq $null) {
 $lastLogin = Never
 }
 Write-Host $user.Name $lastLogin $enabled 
}"

This will return a list of local accounts with the account name, last logon, and if the account is enabled (True/False).
For example: User1 10/31/2015 5:49:56 AM True

Domain Controllers:
Enter the following command in PowerShell.
"Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00"

This will return accounts that have not been logged on to for 35 days, along with various attributes such as the Enabled status and LastLogonDate.

Review the list of accounts returned by the above queries to determine the finding validity for each account reported.

Exclude the following accounts:
Built-in administrator account (Disabled, SID ending in 500)
Built-in guest account (Disabled, SID ending in 501)
Application accounts

If any enabled accounts have not been logged on to within the past 35 days, this is a finding.

Inactive accounts that have been reviewed and deemed to be required must be documented with the ISSO.'

# START_DESCRIBE V-1112
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1112

end

