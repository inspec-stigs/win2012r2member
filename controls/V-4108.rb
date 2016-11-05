# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-4108 - The system must generate an audit event when the audit log reaches a percentage of full threshold.'
control 'V-4108' do
  impact 0.1
  title 'The system must generate an audit event when the audit log reaches a percentage of full threshold.'
  desc 'When the audit log reaches a given percent full, an audit event is written to the security log.  It is recorded as a successful audit event under the category of System.  This option may be especially useful if the audit logs are set to be cleared manually.'
  tag 'stig', 'V-4108'
  tag severity: 'low'
  tag checkid: 'C-47228r2_chk'
  tag fixid: 'F-45849r2_fix'
  tag version: 'WN12-SO-000049'
  tag ruleid: 'SV-52923r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning" to "90" or less.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the systems policy tools.)'
  tag checktext: 'If the system is configured to write to an audit server, or is configured to automatically archive full logs, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Eventlog\Security\

Value Name: WarningLevel

Value Type: REG_DWORD
Value: 90 (or less)'

# START_DESCRIBE V-4108
  
    describe registry_key({
      name: 'WarningLevel',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\Eventlog\Security',
    }) do
      its("WarningLevel") { should eq 90 }
    end

# STOP_DESCRIBE V-4108

end

