# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36661 - Policy must require application account passwords be at least 15 characters in length.'
control 'V-36661' do
  impact 0.5
  title 'Policy must require application account passwords be at least 15 characters in length.'
  desc 'Application/service account passwords must be of sufficient length to prevent being easily cracked.  Application/service accounts that are manually managed must have passwords at least 15 characters in length.'
  tag 'stig', 'V-36661'
  tag severity: 'medium'
  tag checkid: 'C-46842r2_chk'
  tag fixid: 'F-44708r2_fix'
  tag version: 'WN12-00-000010'
  tag ruleid: 'SV-51579r1_rule'
  tag fixtext: 'Establish a site policy that requires application/service account passwords that are manually managed to be at least 15 characters in length.  Ensure the policy is enforced.'
  tag checktext: 'Verify the site has a policy to ensure passwords for manually managed application/service accounts are at least 15 characters in length.  If such a policy does not exist or has not been implemented, this is a finding.'

# START_DESCRIBE V-36661
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36661

end

