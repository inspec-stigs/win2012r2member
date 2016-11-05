# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57641 - Protection methods such as TLS, encrypted VPNs, or IPSEC must be implemented if the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.'
control 'V-57641' do
  impact 0.5
  title 'Protection methods such as TLS, encrypted VPNs, or IPSEC must be implemented if the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, for example, during aggregation, at protocol transformation points, and during packing/unpacking.  These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.  Ensuring the confidentiality of transmitted information requires the operating system to take measures in preparing information for transmission. This can be accomplished via access control and encryption.  Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, operating systems need to support transmission protection mechanisms such as TLS, encrypted VPNs, or IPSEC.'
  tag 'stig', 'V-57641'
  tag severity: 'medium'
  tag checkid: 'C-58463r3_chk'
  tag fixid: 'F-62843r3_fix'
  tag version: 'WN12-00-000019'
  tag ruleid: 'SV-72051r1_rule'
  tag fixtext: 'Configure protection methods such as TLS, encrypted VPNs, or IPSEC when the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process to maintain the confidentiality and integrity.'
  tag checktext: 'If the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, verify protection methods such as TLS, encrypted VPNs, or IPSEC have been implemented.  If protection methods have not been implemented, this is a finding.'

# START_DESCRIBE V-57641
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57641

end

