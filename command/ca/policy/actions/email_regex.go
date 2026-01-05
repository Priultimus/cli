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

// EmailRegexCommand returns the email-regex policy subcommand.
func EmailRegexCommand(ctx context.Context) cli.Command {
	commandName := policycontext.GetPrefixedCommandUsage(ctx, "email-regex")
	return cli.Command{
		Name:  "email-regex",
		Usage: "add or remove email regex patterns",
		UsageText: fmt.Sprintf(`**%s** <regex> [**--remove**] [**--provisioner**=<name>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`, commandName),
		Description: fmt.Sprintf(`**%s** command manages email regex patterns in policies.

Email regex patterns allow flexible matching of email addresses using regular expressions.

## EXAMPLES

Allow any email from example.com using regex
'''
$ step ca policy authority x509 allow email-regex '^.*@example\.com$'
'''

Deny admin emails using regex
'''
$ step ca policy authority x509 deny email-regex '^admin@.*$'
'''

Allow only specific email patterns
'''
$ step ca policy authority x509 allow email-regex '^[a-z]+\.[a-z]+@example\.com$'
'''

Remove a regex pattern
'''
$ step ca policy authority x509 allow email-regex '^.*@example\.com$' --remove
'''

Allow email regex in SSH user certificates
'''
$ step ca policy authority ssh user allow email-regex '^.*@example\.com$'
'''`, commandName),
		Action: command.InjectContext(
			ctx,
			emailRegexAction,
		),
		Flags: []cli.Flag{
			flags.Provisioner,
			cli.BoolFlag{
				Name:  "remove",
				Usage: `removes the provided email regex patterns from the policy instead of adding them`,
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

func emailRegexAction(ctx context.Context) (err error) {
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
		return errors.New("SSH host policy does not support email regex patterns")
	case policycontext.IsSSHUserPolicy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.Ssh.User.Allow.EmailRegex = addOrRemoveArguments(policy.Ssh.User.Allow.EmailRegex, args, shouldRemove)
		case policycontext.IsDeny(ctx):
			policy.Ssh.User.Deny.EmailRegex = addOrRemoveArguments(policy.Ssh.User.Deny.EmailRegex, args, shouldRemove)
		default:
			panic("no allow nor deny context set")
		}
	case policycontext.IsX509Policy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.X509.Allow.EmailRegex = addOrRemoveArguments(policy.X509.Allow.EmailRegex, args, shouldRemove)
		case policycontext.IsDeny(ctx):
			policy.X509.Deny.EmailRegex = addOrRemoveArguments(policy.X509.Deny.EmailRegex, args, shouldRemove)
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
