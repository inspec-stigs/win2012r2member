# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-6832 - The Windows SMB client must be configured to always perform SMB packet signing.'
control 'V-6832' do
  impact 0.5
  title 'The Windows SMB client must be configured to always perform SMB packet signing.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations.  Digitally signed SMB packets aid in preventing man-in-the-middle attacks.  If this policy is enabled, the SMB client will only communicate with an SMB server that performs SMB packet signing.'
  tag 'stig', 'V-6832'
  tag severity: 'medium'
  tag checkid: 'C-47240r2_chk'
  tag fixid: 'F-45861r1_fix'
  tag version: 'WN12-SO-000028'
  tag ruleid: 'SV-52935r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network client: Digitally sign communications (always)" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LanmanWorkstation\Parameters\

Value Name: RequireSecuritySignature

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-6832
  
    describe registry_key({
      name: 'RequireSecuritySignature',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\LanmanWorkstation\Parameters',
    }) do
      its("RequireSecuritySignature") { should eq 1 }
    end

# STOP_DESCRIBE V-6832

end

