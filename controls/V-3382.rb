# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3382 - The system must be configured to meet the minimum session security requirement for NTLM SSP-based clients.'
control 'V-3382' do
  impact 0.5
  title 'The system must be configured to meet the minimum session security requirement for NTLM SSP-based clients.'
  desc 'Microsoft has implemented a variety of security support providers for use with RPC sessions.  All of the options must be enabled to ensure the maximum security level.'
  tag 'stig', 'V-3382'
  tag severity: 'medium'
  tag checkid: 'C-47212r2_chk'
  tag fixid: 'F-45821r1_fix'
  tag version: 'WN12-SO-000069'
  tag ruleid: 'SV-52895r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options selected).'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\MSV1_0\

Value Name: NTLMMinClientSec

Value Type: REG_DWORD
Value: 0x20080000 (537395200)'

# START_DESCRIBE V-3382
  
    describe registry_key({
      name: 'NTLMMinClientSec',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Lsa\MSV1_0',
    }) do
      its("NTLMMinClientSec") { should eq 0x20080000 }
    end

# STOP_DESCRIBE V-3382

end

