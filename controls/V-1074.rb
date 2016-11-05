# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1074 - An approved DoD antivirus program must be installed and used.'
control 'V-1074' do
  impact 1.0
  title 'An approved DoD antivirus program must be installed and used.'
  desc 'Virus scan programs are a primary line of defense against the introduction of viruses and malicious code that can destroy data and even render a computer inoperable.  Utilizing a virus scan program provides the ability to detect malicious code before extensive damage occurs.'
  tag 'stig', 'V-1074'
  tag severity: 'high'
  tag checkid: 'C-61993r1_chk'
  tag fixid: 'F-66889r1_fix'
  tag version: 'WN12-GE-000002'
  tag ruleid: 'SV-52103r2_rule'
  tag fixtext: 'Install McAfee VirusScan Enterprise 8.8 Patch 3 or later on the system.'
  tag checktext: 'Verify a supported DoD antivirus product has been installed on the system.

If McAfee VirusScan Enterprise 8.8 Patch 3 or later is not installed on the system, this is a finding.'

# START_DESCRIBE V-1074
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1074

end

