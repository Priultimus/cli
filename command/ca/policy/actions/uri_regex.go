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

// URIRegexCommand returns the uri-regex policy subcommand.
func URIRegexCommand(ctx context.Context) cli.Command {
	commandName := policycontext.GetPrefixedCommandUsage(ctx, "uri-regex")
	return cli.Command{
		Name:  "uri-regex",
		Usage: "add or remove URI regex patterns",
		UsageText: fmt.Sprintf(`**%s** <regex> [**--remove**] [**--provisioner**=<name>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`, commandName),
		Description: fmt.Sprintf(`**%s** command manages URI regex patterns in policies.

URI regex patterns allow flexible matching of full URIs using regular expressions.
The regex is matched against the complete URI string (scheme://host/path).

## EXAMPLES

Allow HTTPS API URIs using regex
'''
$ step ca policy authority x509 allow uri-regex '^https://.*\.example\.com/api/.*$'
'''

Allow SPIFFE URIs for any workload in a trust domain
'''
$ step ca policy authority x509 allow uri-regex '^spiffe://trust\.domain/.*$'
'''

Deny HTTP (non-secure) URIs using regex
'''
$ step ca policy authority x509 deny uri-regex '^http://.*$'
'''

Allow specific URI path patterns
'''
$ step ca policy authority x509 allow uri-regex '^https://example\.com/api/v[0-9]+/.*$'
'''

Remove a regex pattern
'''
$ step ca policy authority x509 allow uri-regex '^https://.*\.example\.com/api/.*$' --remove
'''`, commandName),
		Action: command.InjectContext(
			ctx,
			uriRegexAction,
		),
		Flags: []cli.Flag{
			flags.Provisioner,
			cli.BoolFlag{
				Name:  "remove",
				Usage: `removes the provided URI regex patterns from the policy instead of adding them`,
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

func uriRegexAction(ctx context.Context) (err error) {
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
		return errors.New("SSH host policy does not support URI regex patterns")
	case policycontext.IsSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support URI regex patterns")
	case policycontext.IsX509Policy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.X509.Allow.UriRegex = addOrRemoveArguments(policy.X509.Allow.UriRegex, args, shouldRemove)
		case policycontext.IsDeny(ctx):
			policy.X509.Deny.UriRegex = addOrRemoveArguments(policy.X509.Deny.UriRegex, args, shouldRemove)
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
