# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57639 - Users must be required to enter a password to access private keys stored on the computer.'
control 'V-57639' do
  impact 0.5
  title 'Users must be required to enter a password to access private keys stored on the computer.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.  The cornerstone of the PKI is the private key used to encrypt or digitally sign information.  If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.  Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.'
  tag 'stig', 'V-57639'
  tag severity: 'medium'
  tag checkid: 'C-58461r2_chk'
  tag fixid: 'F-62841r2_fix'
  tag version: 'WN12-SO-000092'
  tag ruleid: 'SV-72049r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "System cryptography: Force strong key protection for user keys stored on the computer" to "User must enter a password each time they use a key".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Cryptography\

Value Name:  ForceKeyProtection

Type:  REG_DWORD
Value:  2'

# START_DESCRIBE V-57639
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57639

end

