# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36735 - The system must support automated patch management tools to facilitate flaw remediation.'
control 'V-36735' do
  impact 0.5
  title 'The system must support automated patch management tools to facilitate flaw remediation.'
  desc 'The organization (including any contractor to the organization) must promptly install security-relevant software updates (e.g., patches, service packs, hot fixes).  Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed.'
  tag 'stig', 'V-36735'
  tag severity: 'medium'
  tag checkid: 'C-46846r1_chk'
  tag fixid: 'F-44712r1_fix'
  tag version: 'WN12-GE-000024'
  tag ruleid: 'SV-51583r2_rule'
  tag fixtext: 'Establish a process to automatically install security-related software updates.'
  tag checktext: 'Verify the organization has an automated process to install security-related software updates.  If it does not, this is a finding.'

# START_DESCRIBE V-36735
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36735

end

