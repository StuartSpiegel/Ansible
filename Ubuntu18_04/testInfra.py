# CAT II | UBTU-18-010002 | The Ubuntu operating system must initiate session audits at system startup.
def test_ubtu_18_010002(host):
    with host.sudo():
        grub_configurations_starting_with_the_word_linux = host.check_output('grep "^\\s*linux" /boot/grub/grub.cfg')
        grub_configuration_lines_starting_with_the_word_linux = grub_configurations_starting_with_the_word_linux.splitlines()

        auditing_is_enabled_at_startup_for_all_linux_configurations_in_grub = True

        for line in grub_configuration_lines_starting_with_the_word_linux:
            if "audit=1" not in line:
                auditing_is_enabled_at_startup_for_all_linux_configurations_in_grub = False

        assert auditing_is_enabled_at_startup_for_all_linux_configurations_in_grub


# CAT II | UBTU-18-010319 | REMEDIATE | The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the ssh-agent command.
def test_ubtu_18_010319(host):
    audit_rule_for_successful_and_unsuccessful_use_of_ssh_agent = '-a always,exit -S all -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh'
    with host.sudo():
        current_audit_rules_for_ssh_agent = host.check_output("auditctl -l | grep '/usr/bin/ssh-agent'")
        assert audit_rule_for_successful_and_unsuccessful_use_of_ssh_agent in current_audit_rules_for_ssh_agent.splitlines()


# CAT II | UBTU-18-010320 | The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the ssh-keysign command.
def test_ubtu_18_010320(host):
    audit_rule_for_successful_and_unsuccessful_use_of_ssh_keysign = '-a always,exit -S all -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh'
    with host.sudo():
        current_audit_rules_for_ssh_keysign = host.check_output("auditctl -l | grep ssh-keysign")
        assert audit_rule_for_successful_and_unsuccessful_use_of_ssh_keysign in current_audit_rules_for_ssh_keysign.splitlines()


# CAT II | UBTU-18-010321 | UBTU-18-101321 | The Ubuntu operating system must generate audit records for any usage of the setxattr system call.
# CAT II | UBTU-18-010021 | CAT II | UBTU-18-010021 | The Ubuntu operating system must deploy Endpoint Security for
# Linux Threat Prevention (ENSLTP). Validate that the [isectp] package is installed
def test_ubtu_18_010021_isectp_is_installed(host):
    assert host.package("isectp").is_installed


# CAT II | UBTU-18-010021 | The Ubuntu operating system must deploy Endpoint Security for Linux Threat Prevention (ENSLTP).
def test_ubtu_18_010021_isectp_daemon_is_running(host):
    assert host.service("isectp").is_running


# CAT II | UBTU-18-010321 | UBTU-18-101321 | The Ubuntu operating system must generate audit records for any usage of the setxattr system call.
def test_ubtu_18_010321_nonroot_user(host):
    architecture_bits = host.system_info.arch[-2:]
    audit_rules_for_nonroot_setxattr_call = f'-a always,exit -F arch=b{architecture_bits} -S setxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod'
    with host.sudo():
        current_rules_for_nonroot_setxattr_call = host.check_output("auditctl -l | grep setxattr")
        assert audit_rules_for_nonroot_setxattr_call in current_rules_for_nonroot_setxattr_call.splitlines()

# CAT II | UBTU-18-010319 | REMEDIATE | The Ubuntu operating system must generate audit records for
# successful/unsuccessful uses of the ssh-agent command.
def test_ubtu_18_010319(host):
    audit_rule_for_successful_and_unsuccessful_use_of_ssh_agent = '-a always,exit -S all -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh'
    with host.sudo():
        current_audit_rules_for_ssh_agent = host.check_output("auditctl -l | grep '/usr/bin/ssh-agent'")
        assert audit_rule_for_successful_and_unsuccessful_use_of_ssh_agent in current_audit_rules_for_ssh_agent.splitlines()


# CAT II | UBTU-18-010320 | The Ubuntu operating system must generate audit records for successful/unsuccessful uses
# of the ssh-keysign command.
# CAT II | UBTU-18-010320 | The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the ssh-keysign command.
def test_ubtu_18_010320(host):
    audit_rule_for_successful_and_unsuccessful_use_of_ssh_keysign = '-a always,exit -S all -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh'
    with host.sudo():
        current_audit_rules_for_ssh_keysign = host.check_output("auditctl -l | grep ssh-keysign")
        assert audit_rule_for_successful_and_unsuccessful_use_of_ssh_keysign in current_audit_rules_for_ssh_keysign.splitlines()

# CAT II | UBTU-18-010017 | The Ubuntu operating system must be configured so that Advance package Tool (APT) removes
# all software components after updated versions have been installed.
def test_ubtu_18_010017_dependencies(host):
    unattended_updates_configuration = 'Unattended-Upgrade::Remove-Unused-Dependencies "true";'

    with host.sudo():
        current_configuration_line = host.check_output(
            'Unattended-Upgrade::Remove-Unused-Dependencies "true"; | grep -i remove-unused '
            '/etc/apt/apt.conf.d/50unattended-upgrades')
        assert not unattended_updates_configuration in current_configuration_line.splitlines()


# CAT II | UBTU-18-010017 | The Ubuntu Operating System must be configured so that Advance package tool (APT) removes
# all software components after updated versions have been installed.
def test_ubtu_18_010017_kernel(host):
    configuration_line_in_unattended_upgrades_to_remove_unusead_kernel_packages = 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";'

    with host.sudo():
        current_configuration_line_kernel = host.check_output(
            'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true"; | grep -i remove-unused '
            '/etc/apt/apt.conf.d/50unattended-upgrades ')
        assert not configuration_line_in_unattended_upgrades_to_remove_unusead_kernel_packages in current_configuration_line_kernel.splitlines()
def test_ubtu_18_010033(host):
    account_lock_output = host.check_output("grep pam_tally2 /etc/pam.d/common-auth")

    ubuntu_1804_logon_secure = True

    if "onerr=fail" not in account_lock_output and ("deny=1" or "deny=2" or "deny=3" in account_lock_output):
        ubuntu_1804_logon_secure = False
    elif "onerr=fail" in account_lock_output and not ("deny=1" or "deny=2" or "deny=3" in account_lock_output):
        ubuntu_1804_logon_secure = False

    assert ubuntu_1804_logon_secure

