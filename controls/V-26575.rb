# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26575 - The 6to4 IPv6 transition technology must be disabled.'
control 'V-26575' do
  impact 0.5
  title 'The 6to4 IPv6 transition technology must be disabled.'
  desc 'IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility.'
  tag 'stig', 'V-26575'
  tag severity: 'medium'
  tag checkid: 'C-47276r1_chk'
  tag fixid: 'F-45896r1_fix'
  tag version: 'WN12-CC-000007'
  tag ruleid: 'SV-52970r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies -> "Set 6to4 State" to "Enabled: Disabled State".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\TCPIP\v6Transition\

Value Name: 6to4_State

Type: REG_SZ
Value: Disabled'

# START_DESCRIBE V-26575
  
    describe registry_key({
      name: '6to4_State',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\TCPIP\v6Transition',
    }) do
      its("6to4_State") { should eq Disabled }
    end

# STOP_DESCRIBE V-26575

end

