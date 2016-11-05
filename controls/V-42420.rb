# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-42420 - A host-based firewall must be installed and enabled on the system.'
control 'V-42420' do
  impact 0.5
  title 'A host-based firewall must be installed and enabled on the system.'
  desc 'A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on a set of rules.'
  tag 'stig', 'V-42420'
  tag severity: 'medium'
  tag checkid: 'C-48767r2_chk'
  tag fixid: 'F-47956r2_fix'
  tag version: 'WN12-FW-000001'
  tag ruleid: 'SV-55085r1_rule'
  tag fixtext: 'Install and enable a host-based firewall on the system.'
  tag checktext: 'Determine if a host-based firewall is installed and enabled on the system.  If a host-based firewall is not installed and enabled on the system, this is a finding.

The configuration requirements will be determined by the applicable firewall STIG.'

# START_DESCRIBE V-42420
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-42420

end

