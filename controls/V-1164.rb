# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1164 - Outgoing secure channel traffic must be signed when possible.'
control 'V-1164' do
  impact 0.5
  title 'Outgoing secure channel traffic must be signed when possible.'
  desc 'Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but the channel is not integrity checked.  If this policy is enabled, outgoing secure channel traffic will be signed.'
  tag 'stig', 'V-1164'
  tag severity: 'medium'
  tag checkid: 'C-47189r2_chk'
  tag fixid: 'F-45798r1_fix'
  tag version: 'WN12-SO-000014'
  tag ruleid: 'SV-52872r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain member: Digitally sign secure channel data (when possible)" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: SignSecureChannel

Value Type: REG_DWORD
Value: 1

If the value for "Domain Member: Digitally encrypt or sign secure channel data (always)" is set to "Enabled", this can be NA (see V-6831).'

# START_DESCRIBE V-1164
  
    describe registry_key({
      name: 'SignSecureChannel',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\Netlogon\Parameters',
    }) do
      its("SignSecureChannel") { should eq 1 }
    end

# STOP_DESCRIBE V-1164

end

