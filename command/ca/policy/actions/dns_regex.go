package actions

import (
	"context"
	"errors"
	"fmt"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/command/ca/policy/policycontext"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/command"
	"github.com/smallstep/cli/utils/cautils"
)

// DNSRegexCommand returns the dns-regex policy subcommand.
func DNSRegexCommand(ctx context.Context) cli.Command {
	commandName := policycontext.GetPrefixedCommandUsage(ctx, "dns-regex")
	return cli.Command{
		Name:  "dns-regex",
		Usage: "add or remove DNS regex patterns",
		UsageText: fmt.Sprintf(`**%s** <regex> [**--remove**] [**--provisioner**=<name>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`, commandName),
		Description: fmt.Sprintf(`**%s** command manages DNS regex patterns in policies.

DNS regex patterns allow flexible matching of DNS names using regular expressions.
When a DNS name matches a permitted regex pattern, it is allowed (and further 
domain-based checks are skipped). When a DNS name matches an excluded regex 
pattern, it is denied.

## EXAMPLES

Allow any subdomain of example.com using regex
'''
$ step ca policy authority x509 allow dns-regex '^.*\.example\.com$'
'''

Deny internal domains using regex
'''
$ step ca policy authority x509 deny dns-regex '^internal\..*$'
'''

Allow production server naming pattern
'''
$ step ca policy authority x509 allow dns-regex '^prod-[a-z0-9]+-[0-9]+\.example\.com$'
'''

Allow multiple environments
'''
$ step ca policy authority x509 allow dns-regex '^(prod|staging|dev)-.*\.example\.com$'
'''

Remove a regex pattern
'''
$ step ca policy authority x509 allow dns-regex '^.*\.example\.com$' --remove
'''

Allow DNS regex in SSH host certificates
'''
$ step ca policy authority ssh host allow dns-regex '^.*\.internal\.example\.com$'
'''`, commandName),
		Action: command.InjectContext(
			ctx,
			dnsRegexAction,
		),
		Flags: []cli.Flag{
			flags.Provisioner,
			cli.BoolFlag{
				Name:  "remove",
				Usage: `removes the provided DNS regex patterns from the policy instead of adding them`,
			},
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminSubject,
			flags.AdminProvisioner,
			flags.AdminPasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
	}
}

func dnsRegexAction(ctx context.Context) (err error) {
	var (
		provisioner = retrieveAndUnsetProvisionerFlagIfRequired(ctx)
		clictx      = command.CLIContextFromContext(ctx)
		args        = clictx.Args()
	)

	if len(args) == 0 {
		return errs.TooFewArguments(clictx)
	}

	client, err := cautils.NewAdminClient(clictx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	policy, err := retrieveAndInitializePolicy(ctx, client, provisioner)
	if err != nil {
		return fmt.Errorf("error retrieving policy: %w", err)
	}

	shouldRemove := clictx.Bool("remove")

	switch {
	case policycontext.IsSSHHostPolicy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.Ssh.Host.Allow.DnsRegex = addOrRemoveArguments(policy.Ssh.Host.Allow.DnsRegex, args, shouldRemove)
		case policycontext.IsDeny(ctx):
			policy.Ssh.Host.Deny.DnsRegex = addOrRemoveArguments(policy.Ssh.Host.Deny.DnsRegex, args, shouldRemove)
		default:
			panic("no allow nor deny context set")
		}
	case policycontext.IsSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support DNS regex patterns")
	case policycontext.IsX509Policy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.X509.Allow.DnsRegex = addOrRemoveArguments(policy.X509.Allow.DnsRegex, args, shouldRemove)
		case policycontext.IsDeny(ctx):
			policy.X509.Deny.DnsRegex = addOrRemoveArguments(policy.X509.Deny.DnsRegex, args, shouldRemove)
		default:
			panic("no allow nor deny context set")
		}
	default:
		panic("no SSH nor X.509 context set")
	}

	updatedPolicy, err := updatePolicy(ctx, client, policy, provisioner)
	if err != nil {
		return fmt.Errorf("error updating policy: %w", err)
	}

	return prettyPrint(updatedPolicy)
}
