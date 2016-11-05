# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21956 - IPv6 TCP data retransmissions must be configured to prevent resources from becoming exhausted.'
control 'V-21956' do
  impact 0.1
  title 'IPv6 TCP data retransmissions must be configured to prevent resources from becoming exhausted.'
  desc 'Configuring Windows to limit the number of times that IPv6 TCP retransmits unacknowledged data segments before aborting the attempt helps prevent resources from becoming exhausted.'
  tag 'stig', 'V-21956'
  tag severity: 'low'
  tag checkid: 'C-47487r3_chk'
  tag fixid: 'F-46107r2_fix'
  tag version: 'WN12-SO-000047'
  tag ruleid: 'SV-53181r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" to "3" or less.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the systems policy tools.)'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\

Value Name:  TcpMaxDataRetransmissions

Value Type:  REG_DWORD
Value:  3 (or less)'

# START_DESCRIBE V-21956
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-21956

end

