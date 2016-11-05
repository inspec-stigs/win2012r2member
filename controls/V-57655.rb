# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57655 - The operating system must be configured such that emergency administrator accounts are never automatically removed or disabled.'
control 'V-57655' do
  impact 0.5
  title 'The operating system must be configured such that emergency administrator accounts are never automatically removed or disabled.'
  desc 'Emergency administrator accounts are privileged accounts which are established in response to crisis situations where the need for rapid account activation is required.  Therefore, emergency account activation may bypass normal account authorization processes.  If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.  Emergency administrator accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available).  Infrequently used accounts also remain available and are not subject to automatic termination dates.  However, an emergency administrator account is normally a different account which is created for use by vendors or system maintainers.  To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.'
  tag 'stig', 'V-57655'
  tag severity: 'medium'
  tag checkid: 'C-58477r2_chk'
  tag fixid: 'F-62857r3_fix'
  tag version: 'WN12-GE-000057'
  tag ruleid: 'SV-72065r1_rule'
  tag fixtext: 'Ensure emergency accounts are not configured to automatically expire.'
  tag checktext: 'Verify the operating system does not automatically disable emergency accounts.  If it does not, this is a finding.

Determine if emergency accounts are used and identify any that may be in existence.
For Domain Accounts:
Open PowerShell.
Run the command "Search-ADAccount -AccountExpiring" to determine if account expiration dates have been configured on any emergency accounts.

Local accounts:
Run "Net user <username>".  This will list the account properties, including "Account Expires".'

# START_DESCRIBE V-57655
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57655

end

