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

// PrincipalRegexCommand returns the principal-regex policy subcommand.
func PrincipalRegexCommand(ctx context.Context) cli.Command {
	commandName := policycontext.GetPrefixedCommandUsage(ctx, "principal-regex")
	return cli.Command{
		Name:  "principal-regex",
		Usage: "add or remove principal regex patterns",
		UsageText: fmt.Sprintf(`**%s** <regex> [**--remove**] [**--provisioner**=<name>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`, commandName),
		Description: fmt.Sprintf(`**%s** command manages principal regex patterns in SSH policies.

Principal regex patterns allow flexible matching of SSH certificate principals
using regular expressions.

## EXAMPLES

Allow user principals matching a pattern in SSH user certificates
'''
$ step ca policy authority ssh user allow principal-regex '^user-.*$'
'''

Deny root principal using regex in SSH user certificates
'''
$ step ca policy authority ssh user deny principal-regex '^root$'
'''

Allow host principals matching a naming pattern in SSH host certificates
'''
$ step ca policy authority ssh host allow principal-regex '^server-[0-9]+\.example\.com$'
'''

Allow service account principals
'''
$ step ca policy authority ssh user allow principal-regex '^svc-[a-z]+-[a-z]+$'
'''

Remove a regex pattern
'''
$ step ca policy authority ssh user allow principal-regex '^user-.*$' --remove
'''`, commandName),
		Action: command.InjectContext(
			ctx,
			principalRegexAction,
		),
		Flags: []cli.Flag{
			flags.Provisioner,
			cli.BoolFlag{
				Name:  "remove",
				Usage: `removes the provided principal regex patterns from the policy instead of adding them`,
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

func principalRegexAction(ctx context.Context) (err error) {
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
			policy.Ssh.Host.Allow.PrincipalRegex = addOrRemoveArguments(policy.Ssh.Host.Allow.PrincipalRegex, args, shouldRemove)
		case policycontext.IsDeny(ctx):
			policy.Ssh.Host.Deny.PrincipalRegex = addOrRemoveArguments(policy.Ssh.Host.Deny.PrincipalRegex, args, shouldRemove)
		default:
			panic("no allow nor deny context set")
		}
	case policycontext.IsSSHUserPolicy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.Ssh.User.Allow.PrincipalRegex = addOrRemoveArguments(policy.Ssh.User.Allow.PrincipalRegex, args, shouldRemove)
		case policycontext.IsDeny(ctx):
			policy.Ssh.User.Deny.PrincipalRegex = addOrRemoveArguments(policy.Ssh.User.Deny.PrincipalRegex, args, shouldRemove)
		default:
			panic("no allow nor deny context set")
		}
	case policycontext.IsX509Policy(ctx):
		return errors.New("X.509 policy does not support principal regex patterns")
	default:
		panic("no SSH nor X.509 context set")
	}

	updatedPolicy, err := updatePolicy(ctx, client, policy, provisioner)
	if err != nil {
		return fmt.Errorf("error updating policy: %w", err)
	}

	return prettyPrint(updatedPolicy)
}

