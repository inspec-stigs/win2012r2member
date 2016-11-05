# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36664 - The system must not use removable media as the boot loader.'
control 'V-36664' do
  impact 1.0
  title 'The system must not use removable media as the boot loader.'
  desc 'Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader.'
  tag 'stig', 'V-36664'
  tag severity: 'high'
  tag checkid: 'C-46837r3_chk'
  tag fixid: 'F-44703r2_fix'
  tag version: 'WN12-00-000003'
  tag ruleid: 'SV-51574r3_rule'
  tag fixtext: 'Configure the system to use a boot loader installed on fixed media.

Restrictions may also be applied through hypervisor configuration settings for virtual machines.'
  tag checktext: 'Verify whether the system BIOS or controller allows removable media for the boot loader.  If it does, this is a finding.

If access is restricted by way of hypervisor configuration settings on virtual systems, this would not be a finding.'

# START_DESCRIBE V-36664
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36664

end

