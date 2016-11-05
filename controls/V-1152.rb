# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1152 - Anonymous access to the registry must be restricted.'
control 'V-1152' do
  impact 1.0
  title 'Anonymous access to the registry must be restricted.'
  desc 'The registry is integral to the function, security, and stability of the Windows system.  Some processes may require anonymous access to the registry.  This must be limited to properly protect the system.'
  tag 'stig', 'V-1152'
  tag severity: 'high'
  tag checkid: 'C-66339r1_chk'
  tag fixid: 'F-71725r1_fix'
  tag version: 'WN12-RG-000004'
  tag ruleid: 'SV-52864r2_rule'
  tag fixtext: 'Maintain the default permissions of the following registry key:

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\

Administrators - Full Control
Backup Operators - Read (This key only)
LOCAL SERVICE - Read'
  tag checktext: 'Run "Regedit".
Navigate to the following registry key:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\

If the key does not exist, this is a finding.

Review the permissions.

If the default permissions listed below have been changed, this is a finding.

Administrators - Full Control
Backup Operators - Read (This key only)
LOCAL SERVICE - Read'

# START_DESCRIBE V-1152
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1152

end

