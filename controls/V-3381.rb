# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3381 - The system must be configured to the required LDAP client signing level.'
control 'V-3381' do
  impact 0.5
  title 'The system must be configured to the required LDAP client signing level.'
  desc 'This setting controls the signing requirements for LDAP clients.  This setting must be set to Negotiate signing or Require signing, depending on the environment and type of LDAP server in use.'
  tag 'stig', 'V-3381'
  tag severity: 'medium'
  tag checkid: 'C-47211r2_chk'
  tag fixid: 'F-45820r1_fix'
  tag version: 'WN12-SO-000068'
  tag ruleid: 'SV-52894r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: LDAP client signing requirements" to "Negotiate signing" at a minimum.'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LDAP\

Value Name: LDAPClientIntegrity

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-3381
  
    describe registry_key({
      name: 'LDAPClientIntegrity',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\LDAP',
    }) do
      its("LDAPClientIntegrity") { should eq 1 }
    end

# STOP_DESCRIBE V-3381

end

