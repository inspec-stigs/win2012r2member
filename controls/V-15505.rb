# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15505 - The HBSS McAfee Agent must be installed.'
control 'V-15505' do
  impact 0.5
  title 'The HBSS McAfee Agent must be installed.'
  desc ''
  tag 'stig', 'V-15505'
  tag severity: 'medium'
  tag checkid: 'C-47316r2_chk'
  tag fixid: 'F-45937r1_fix'
  tag version: 'WN12-GE-000019'
  tag ruleid: 'SV-53010r1_rule'
  tag fixtext: 'Deploy the McAfee Agent as detailed in accordance with the DoD HBSS STIG.'
  tag checktext: 'Search for the file FrameworkService.exe (by default in the \Program Files\McAfee\Common Framework\ directory) and check that the version is 4 or above.

Also verify that the Service "McAfee Framework Service" is running.

If either of these conditions does not exist, this is a finding.'

# START_DESCRIBE V-15505
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-15505

end

