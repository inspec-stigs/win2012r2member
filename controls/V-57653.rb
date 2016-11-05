# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57653 - The operating system must automatically remove or disable temporary user accounts after 72 hours.'
control 'V-57653' do
  impact 0.5
  title 'The operating system must automatically remove or disable temporary user accounts after 72 hours.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.  Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.  If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.  To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.'
  tag 'stig', 'V-57653'
  tag severity: 'medium'
  tag checkid: 'C-58475r1_chk'
  tag fixid: 'F-62855r3_fix'
  tag version: 'WN12-GE-000056'
  tag ruleid: 'SV-72063r1_rule'
  tag fixtext: 'Configure temporary user accounts to be automatically disabled after 72 hours.

Domain account can be configured with an account expiration date, under Account properties.

Local accounts can be configured to expire with the command "Net user <username> /expires:<date>".

Delete any temporary user accounts that are no longer necessary.'
  tag checktext: 'Verify the operating system automatically disables temporary user accounts after 72 hours.  If it does not, this is a finding.

Determine if temporary user accounts are used and identify any that may be in existence.
For Domain Accounts:
Open PowerShell.
Run the command "Search-ADAccount -AccountExpiring" to determine if account expiration dates have been configured on any temporary accounts.
For any accounts returned, run the command "Get-ADUser -Identity <Name> -Property WhenCreated" to determine when the account was created.

Local accounts:
Run "Net user <username>".  This will list the account properties, including "Account Expires".'

# START_DESCRIBE V-57653
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57653

end

