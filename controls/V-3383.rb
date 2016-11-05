# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3383 - The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.'
control 'V-3383' do
  impact 0.5
  title 'The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.'
  desc 'This setting ensures that the system uses algorithms that are FIPS-compliant for encryption, hashing, and signing.  FIPS-compliant algorithms meet specific standards established by the U.S. Government and must be the algorithms used for all OS encryption functions.'
  tag 'stig', 'V-3383'
  tag severity: 'medium'
  tag checkid: 'C-47213r2_chk'
  tag fixid: 'F-45822r1_fix'
  tag version: 'WN12-SO-000074'
  tag ruleid: 'SV-52896r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\

Value Name: Enabled

Value Type: REG_DWORD
Value: 1
 
Warning: Clients with this setting enabled will not be able to communicate via digitally encrypted or signed protocols with servers that do not support these algorithms.  Both the browser and web server must be configured to use TLS, or the browser will not be able to connect to a secure site.'

# START_DESCRIBE V-3383
  
    describe registry_key({
      name: 'Enabled',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy',
    }) do
      its("Enabled") { should eq 1 }
    end

# STOP_DESCRIBE V-3383

end

