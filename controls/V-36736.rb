# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36736 - The system must query the certification authority to determine whether a public key certificate has been revoked before accepting the certificate for authentication purposes.'
control 'V-36736' do
  impact 0.5
  title 'The system must query the certification authority to determine whether a public key certificate has been revoked before accepting the certificate for authentication purposes.'
  desc 'Failure to verify a certificates revocation status can result in the system accepting a revoked, and therefore unauthorized, certificate.  This could result in the installation of unauthorized software or a connection for rogue networks, depending on the use for which the certificate is intended.   Querying for certificate revocation mitigates the risk that the system will accept an unauthorized certificate.'
  tag 'stig', 'V-36736'
  tag severity: 'medium'
  tag checkid: 'C-46847r1_chk'
  tag fixid: 'F-44713r1_fix'
  tag version: 'WN12-GE-000025'
  tag ruleid: 'SV-51584r1_rule'
  tag fixtext: 'Install software that  provides certificate validation and revocation checking.'
  tag checktext: 'Verify the system has software installed and running that provides certificate validation and revocation checking.  If it does not, this is a finding.'

# START_DESCRIBE V-36736
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36736

end

