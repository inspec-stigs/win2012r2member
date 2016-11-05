# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15696 - The Mapper I/O network protocol (LLTDIO) driver must be disabled.'
control 'V-15696' do
  impact 0.5
  title 'The Mapper I/O network protocol (LLTDIO) driver must be disabled.'
  desc 'The Mapper I/O network protocol (LLTDIO) driver allows the discovery of the connected network and allows various options to be enabled.  Disabling this helps protect the system from potentially discovering and connecting to unauthorized devices.'
  tag 'stig', 'V-15696'
  tag severity: 'medium'
  tag checkid: 'C-47378r2_chk'
  tag fixid: 'F-45998r1_fix'
  tag version: 'WN12-CC-000001'
  tag ruleid: 'SV-53072r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery -> "Turn on Mapper I/O (LLTDIO) driver" to "Disabled".'
  tag checktext: 'If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\LLTD\

Value Name: AllowLLTDIOOndomain
Value Name: AllowLLTDIOOnPublicNet
Value Name: EnableLLTDIO
Value Name: ProhibitLLTDIOOnPrivateNet

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-15696
  
    describe registry_key({
      name: 'AllowLLTDIOOndomain',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\LLTD',
    }) do
      its("AllowLLTDIOOndomain") { should eq 0 }
    end

# STOP_DESCRIBE V-15696

end

