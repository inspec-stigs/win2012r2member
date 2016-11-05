# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15667 - Network Bridges must be prohibited in Windows.'
control 'V-15667' do
  impact 0.5
  title 'Network Bridges must be prohibited in Windows.'
  desc 'A Network Bridge can connect two or more network segments, allowing unauthorized access or exposure of sensitive data.  This setting prevents a Network Bridge from being installed and configured.'
  tag 'stig', 'V-15667'
  tag severity: 'medium'
  tag checkid: 'C-47321r2_chk'
  tag fixid: 'F-45941r1_fix'
  tag version: 'WN12-CC-000004'
  tag ruleid: 'SV-53014r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections -> "Prohibit installation and configuration of Network Bridge on your DNS domain network" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Network Connections\

Value Name: NC_AllowNetBridge_NLA

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-15667
  
    describe registry_key({
      name: 'NC_AllowNetBridge_NLA',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\Network Connections',
    }) do
      its("NC_AllowNetBridge_NLA") { should eq 0 }
    end

# STOP_DESCRIBE V-15667

end

