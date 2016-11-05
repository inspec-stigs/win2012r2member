# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21961 - All Direct Access traffic must be routed through the internal network.'
control 'V-21961' do
  impact 0.1
  title 'All Direct Access traffic must be routed through the internal network.'
  desc 'Routing all Direct Access  traffic through the internal network allows monitoring and prevents split tunneling.'
  tag 'stig', 'V-21961'
  tag severity: 'low'
  tag checkid: 'C-47489r1_chk'
  tag fixid: 'F-46109r1_fix'
  tag version: 'WN12-CC-000006'
  tag ruleid: 'SV-53183r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections -> "Route all traffic through the internal network" to "Enabled: Enabled State".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\TCPIP\v6Transition\

Value Name: Force_Tunneling

Type: REG_SZ
Value: Enabled'

# START_DESCRIBE V-21961
  
    describe registry_key({
      name: 'Force_Tunneling',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\TCPIP\v6Transition',
    }) do
      its("Force_Tunneling") { should eq Enabled }
    end

# STOP_DESCRIBE V-21961

end

