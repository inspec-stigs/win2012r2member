# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1162 - The Windows SMB server must perform SMB packet signing when possible.'
control 'V-1162' do
  impact 0.5
  title 'The Windows SMB server must perform SMB packet signing when possible.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations.   Digitally signed SMB packets aid in preventing man-in-the-middle attacks.  If this policy is enabled, the SMB server will negotiate SMB packet signing as requested by the client.'
  tag 'stig', 'V-1162'
  tag severity: 'medium'
  tag checkid: 'C-47187r2_chk'
  tag fixid: 'F-45796r1_fix'
  tag version: 'WN12-SO-000033'
  tag ruleid: 'SV-52870r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network server: Digitally sign communications (if client agrees)" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LanManServer\Parameters\

Value Name: EnableSecuritySignature

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-1162
  
    describe registry_key({
      name: 'EnableSecuritySignature',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\LanManServer\Parameters',
    }) do
      its("EnableSecuritySignature") { should eq 1 }
    end

# STOP_DESCRIBE V-1162

end

