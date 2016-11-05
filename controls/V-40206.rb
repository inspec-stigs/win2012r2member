# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-40206 - The Smart Card Removal Policy service must be configured to automatic.'
control 'V-40206' do
  impact 0.5
  title 'The Smart Card Removal Policy service must be configured to automatic.'
  desc 'The automatic start of the Smart Card Removal Policy service is required to support the smart card removal behavior requirement.'
  tag 'stig', 'V-40206'
  tag severity: 'medium'
  tag checkid: 'C-46956r1_chk'
  tag fixid: 'F-45191r1_fix'
  tag version: 'WN12-SV-000106'
  tag ruleid: 'SV-52165r2_rule'
  tag fixtext: 'Configure the Startup Type for the Smart Card Removal Policy service to "Automatic".'
  tag checktext: 'Verify the Smart Card Removal Policy service is configured to "Automatic". 

Run "Services.msc".

If the Startup Type for Smart Card Removal Policy is not set to Automatic, this is a finding.'

# START_DESCRIBE V-40206
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-40206

end

