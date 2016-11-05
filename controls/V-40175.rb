# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-40175 - The antivirus program signature files must be kept updated.'
control 'V-40175' do
  impact 1.0
  title 'The antivirus program signature files must be kept updated.'
  desc 'Virus scan programs are a primary line of defense against the introduction of viruses and malicious code that can destroy data and even render a computer inoperable.  Utilizing the virus scan program provides the ability to detect malicious code before extensive damage occurs.  Updated virus scan data files help protect a system, as new malware is identified by the software vendors on a regular basis.'
  tag 'stig', 'V-40175'
  tag severity: 'high'
  tag checkid: 'C-46945r1_chk'
  tag fixid: 'F-45159r1_fix'
  tag version: 'WN12-GE-000003'
  tag ruleid: 'SV-52133r2_rule'
  tag fixtext: 'Configure the antivirus program to update the signature file at least every 7 days.  More frequent (daily) updates are recommended.'
  tag checktext: 'If V-19910 from an antivirus STIG has been applied to the system, this is NA.

Verify the signature file for the virus scan program is up to date.

If the antivirus program signature file is not dated within the past 7 days, this is a finding.

The version numbers and the date of the signature file can generally be checked by starting the antivirus program. The information may appear in the antivirus window or be available in the Help > About window. The location varies from product to product.'

# START_DESCRIBE V-40175
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-40175

end

