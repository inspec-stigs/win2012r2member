# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1166 - The Windows SMB client must be enabled to perform SMB packet signing when possible.'
control 'V-1166' do
  impact 0.5
  title 'The Windows SMB client must be enabled to perform SMB packet signing when possible.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations.   If this policy is enabled, the SMB client will request packet signing when communicating with an SMB server that is enabled or required to perform SMB packet signing.'
  tag 'stig', 'V-1166'
  tag severity: 'medium'
  tag checkid: 'C-47191r2_chk'
  tag fixid: 'F-45800r1_fix'
  tag version: 'WN12-SO-000029'
  tag ruleid: 'SV-52874r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network client: Digitally sign communications (if server agrees)" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LanmanWorkstation\Parameters\

Value Name: EnableSecuritySignature

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-1166
  
    describe registry_key({
      name: 'EnableSecuritySignature',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\LanmanWorkstation\Parameters',
    }) do
      its("EnableSecuritySignature") { should eq 1 }
    end

# STOP_DESCRIBE V-1166

end

