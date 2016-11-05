# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-6840 - System mechanisms must be implemented to enforce automatic expiration of passwords.'
control 'V-6840' do
  impact 0.5
  title 'System mechanisms must be implemented to enforce automatic expiration of passwords.'
  desc 'Passwords that do not expire or are reused increase the exposure of a password with greater probability of being discovered or cracked.'
  tag 'stig', 'V-6840'
  tag severity: 'medium'
  tag checkid: 'C-47245r4_chk'
  tag fixid: 'F-45865r2_fix'
  tag version: 'WN12-GE-000016'
  tag ruleid: 'SV-52939r3_rule'
  tag fixtext: 'Configure all passwords to expire.  Ensure "Password never expires" is not checked on any accounts.  Document any exceptions with the ISSO.'
  tag checktext: 'Run the DUMPSEC utility.
Select "Dump Users as Table" from the "Report" menu.
Select the following fields, and click "Add" for each entry:

UserName
SID
PswdExpires
AcctDisabled
Groups

If any accounts have "No" in the "PswdExpires" column, this is a finding. 

The following are exempt from this requirement:
Application Accounts
Domain accounts requiring smart card (CAC/PIV)

The following PowerShell command may be used on domain controllers to list accounts with the Password Never Expires flag:
Search-ADAccount -PasswordNeverExpires -UsersOnly'

# START_DESCRIBE V-6840
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-6840

end

