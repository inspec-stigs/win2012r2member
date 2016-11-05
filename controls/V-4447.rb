# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-4447 - The Remote Desktop Session Host must require secure RPC communications.'
control 'V-4447' do
  impact 0.5
  title 'The Remote Desktop Session Host must require secure RPC communications.'
  desc 'Allowing unsecure RPC communication exposes the system to man-in-the-middle attacks and data disclosure attacks.  A man-in-the-middle attack occurs when an intruder captures packets between a client and server and modifies them before allowing the packets to be exchanged.  Usually the attacker will modify the information in the packets in an attempt to cause either the client or server to reveal sensitive information.'
  tag 'stig', 'V-4447'
  tag severity: 'medium'
  tag checkid: 'C-47237r2_chk'
  tag fixid: 'F-45858r2_fix'
  tag version: 'WN12-CC-000130'
  tag ruleid: 'SV-52932r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security -> "Require secure RPC communication" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fEncryptRPCTraffic

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-4447
  
    describe registry_key({
      name: 'fEncryptRPCTraffic',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Terminal Services',
    }) do
      its("fEncryptRPCTraffic") { should eq 1 }
    end

# STOP_DESCRIBE V-4447

end

