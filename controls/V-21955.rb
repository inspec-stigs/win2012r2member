# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21955 - IPv6 source routing must be configured to the highest protection level.'
control 'V-21955' do
  impact 0.1
  title 'IPv6 source routing must be configured to the highest protection level.'
  desc 'Configuring the system to disable IPv6 source routing protects against spoofing.'
  tag 'stig', 'V-21955'
  tag severity: 'low'
  tag checkid: 'C-47486r2_chk'
  tag fixid: 'F-46106r1_fix'
  tag version: 'WN12-SO-000037'
  tag ruleid: 'SV-53180r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the systems policy tools.)'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\

Value Name: DisableIPSourceRouting

Type: REG_DWORD
Value: 2'

# START_DESCRIBE V-21955
  
    describe registry_key({
      name: 'DisableIPSourceRouting',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters',
    }) do
      its("DisableIPSourceRouting") { should eq 2 }
    end

# STOP_DESCRIBE V-21955

end

