# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36666 - Policy must require that system administrators (SAs) be trained for the operating systems used by systems under their control.'
control 'V-36666' do
  impact 0.5
  title 'Policy must require that system administrators (SAs) be trained for the operating systems used by systems under their control.'
  desc 'If SAs are assigned to systems running operating systems for which they have no training, these systems are at additional risk of unintentional misconfiguration that may result in vulnerabilities or decreased availability of the system.'
  tag 'stig', 'V-36666'
  tag severity: 'medium'
  tag checkid: 'C-46840r2_chk'
  tag fixid: 'F-44706r1_fix'
  tag version: 'WN12-00-000006'
  tag ruleid: 'SV-51577r1_rule'
  tag fixtext: 'Establish site policy that requires SAs be trained for all operating systems running on systems under their control.'
  tag checktext: 'Determine whether the site has a policy that requires SAs be trained for all operating systems running on systems under their control.  If  the site does not have a policy requiring SAs be trained for all operating systems under their control, this is a finding.'

# START_DESCRIBE V-36666
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36666

end

