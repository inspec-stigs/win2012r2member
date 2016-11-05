# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15697 - The Responder network protocol driver must be disabled.'
control 'V-15697' do
  impact 0.5
  title 'The Responder network protocol driver must be disabled.'
  desc 'The Responder network protocol driver allows a computer to be discovered and located on a network.  Disabling this helps protect the system from potentially being discovered and connected to by unauthorized devices.'
  tag 'stig', 'V-15697'
  tag severity: 'medium'
  tag checkid: 'C-47387r2_chk'
  tag fixid: 'F-46007r1_fix'
  tag version: 'WN12-CC-000002'
  tag ruleid: 'SV-53081r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery -> "Turn on Responder (RSPNDR) driver" to "Disabled".'
  tag checktext: 'If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\LLTD\

Value Name: AllowRspndrOndomain
Value Name: AllowRspndrOnPublicNet
Value Name: EnableRspndr
Value Name: ProhibitRspndrOnPrivateNet

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-15697
  
    describe registry_key({
      name: 'AllowRspndrOndomain',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\LLTD',
    }) do
      its("AllowRspndrOndomain") { should eq 0 }
    end

# STOP_DESCRIBE V-15697

end

