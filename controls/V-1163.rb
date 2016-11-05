# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1163 - Outgoing secure channel traffic must be encrypted when possible.'
control 'V-1163' do
  impact 0.5
  title 'Outgoing secure channel traffic must be encrypted when possible.'
  desc 'Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted.  If this policy is enabled, outgoing secure channel traffic will be encrypted.'
  tag 'stig', 'V-1163'
  tag severity: 'medium'
  tag checkid: 'C-47188r2_chk'
  tag fixid: 'F-45797r1_fix'
  tag version: 'WN12-SO-000013'
  tag ruleid: 'SV-52871r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain member: Digitally encrypt secure channel data (when possible)" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: SealSecureChannel

Value Type: REG_DWORD
Value: 1

If the value for "Domain Member: Digitally encrypt or sign secure channel data (always)" is set to "Enabled", this can be NA (see V-6831).'

# START_DESCRIBE V-1163
  
    describe registry_key({
      name: 'SealSecureChannel',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\Netlogon\Parameters',
    }) do
      its("SealSecureChannel") { should eq 1 }
    end

# STOP_DESCRIBE V-1163

end

