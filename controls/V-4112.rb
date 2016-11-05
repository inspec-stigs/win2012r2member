# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-4112 - The system must be configured to disable the Internet Router Discovery Protocol (IRDP).'
control 'V-4112' do
  impact 0.1
  title 'The system must be configured to disable the Internet Router Discovery Protocol (IRDP).'
  desc 'The Internet Router Discovery Protocol (IRDP) is used to detect and configure default gateway addresses on the computer.  If a router is impersonated on a network, traffic could be routed through the compromised system.'
  tag 'stig', 'V-4112'
  tag severity: 'low'
  tag checkid: 'C-47231r2_chk'
  tag fixid: 'F-45852r2_fix'
  tag version: 'WN12-SO-000044'
  tag ruleid: 'SV-52926r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)" to "Disabled".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the systems policy tools.)'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Tcpip\Parameters\

Value Name: PerformRouterDiscovery

Value Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-4112
  
    describe registry_key({
      name: 'PerformRouterDiscovery',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\Tcpip\Parameters',
    }) do
      its("PerformRouterDiscovery") { should eq 0 }
    end

# STOP_DESCRIBE V-4112

end

