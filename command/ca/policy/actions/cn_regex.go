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

// CommonNameRegexCommand returns the cn-regex policy subcommand.
func CommonNameRegexCommand(ctx context.Context) cli.Command {
	commandName := policycontext.GetPrefixedCommandUsage(ctx, "cn-regex")
	return cli.Command{
		Name:  "cn-regex",
		Usage: "add or remove common name regex patterns",
		UsageText: fmt.Sprintf(`**%s** <regex> [**--remove**] [**--provisioner**=<name>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`, commandName),
		Description: fmt.Sprintf(`**%s** command manages common name regex patterns in policies.

Common name regex patterns allow flexible matching of certificate Subject Common Names
using regular expressions.

## EXAMPLES

Allow any subdomain of example.com in Common Name
'''
$ step ca policy authority x509 allow cn-regex '^.*\.example\.com$'
'''

Deny test certificates using regex
'''
$ step ca policy authority x509 deny cn-regex '^test-.*$'
'''

Allow production server naming pattern
'''
$ step ca policy authority x509 allow cn-regex '^prod-[a-z]+-[0-9]+\.example\.com$'
'''

Remove a regex pattern
'''
$ step ca policy authority x509 allow cn-regex '^.*\.example\.com$' --remove
'''`, commandName),
		Action: command.InjectContext(
			ctx,
			commonNameRegexAction,
		),
		Flags: []cli.Flag{
			flags.Provisioner,
			cli.BoolFlag{
				Name:  "remove",
				Usage: `removes the provided common name regex patterns from the policy instead of adding them`,
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

func commonNameRegexAction(ctx context.Context) (err error) {
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
		return errors.New("SSH host policy does not support common name regex patterns")
	case policycontext.IsSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support common name regex patterns")
	case policycontext.IsX509Policy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.X509.Allow.CommonNameRegex = addOrRemoveArguments(policy.X509.Allow.CommonNameRegex, args, shouldRemove)
		case policycontext.IsDeny(ctx):
			policy.X509.Deny.CommonNameRegex = addOrRemoveArguments(policy.X509.Deny.CommonNameRegex, args, shouldRemove)
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
