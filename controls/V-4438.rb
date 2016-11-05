# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-4438 - The system must limit how many times unacknowledged TCP data is retransmitted.'
control 'V-4438' do
  impact 0.1
  title 'The system must limit how many times unacknowledged TCP data is retransmitted.'
  desc 'In a SYN flood attack, the attacker sends a continuous stream of SYN packets to a server, and the server leaves the half-open connections open until it is overwhelmed and is no longer able to respond to legitimate requests.'
  tag 'stig', 'V-4438'
  tag severity: 'low'
  tag checkid: 'C-47234r3_chk'
  tag fixid: 'F-45855r3_fix'
  tag version: 'WN12-SO-000048'
  tag ruleid: 'SV-52929r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" to "3" or less.   

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the systems policy tools.)'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\

Value Name:  TcpMaxDataRetransmissions

Value Type:  REG_DWORD
Value:  3 (or less)'

# START_DESCRIBE V-4438
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-4438

end

