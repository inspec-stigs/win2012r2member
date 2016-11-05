# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-4110 - The system must be configured to prevent IP source routing.'
control 'V-4110' do
  impact 0.1
  title 'The system must be configured to prevent IP source routing.'
  desc 'Configuring the system to disable IP source routing protects against spoofing.'
  tag 'stig', 'V-4110'
  tag severity: 'low'
  tag checkid: 'C-47229r2_chk'
  tag fixid: 'F-45850r2_fix'
  tag version: 'WN12-SO-000038'
  tag ruleid: 'SV-52924r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the systems policy tools.)'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Tcpip\Parameters\

Value Name: DisableIPSourceRouting

Value Type: REG_DWORD
Value: 2'

# START_DESCRIBE V-4110
  
    describe registry_key({
      name: 'DisableIPSourceRouting',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\Tcpip\Parameters',
    }) do
      its("DisableIPSourceRouting") { should eq 2 }
    end

# STOP_DESCRIBE V-4110

end

