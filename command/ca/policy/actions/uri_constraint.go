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

// URIConstraintCommand returns the uri-constraint policy subcommand.
func URIConstraintCommand(ctx context.Context) cli.Command {
	commandName := policycontext.GetPrefixedCommandUsage(ctx, "uri-constraint")
	return cli.Command{
		Name:  "uri-constraint",
		Usage: "add or remove enhanced URI constraints (with scheme and path support)",
		UsageText: fmt.Sprintf(`**%s** <constraint> [**--remove**] [**--provisioner**=<name>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`, commandName),
		Description: fmt.Sprintf(`**%s** command manages enhanced URI constraints in policies.

Enhanced URI constraints allow you to match URIs based on scheme, domain, and path,
providing more granular control than simple domain-based URI matching.

## CONSTRAINT FORMAT

The constraint can be specified in the following formats:
  - **domain** - Match any URI with this domain (backwards compatible)
  - **scheme://domain** - Match URIs with this scheme and domain
  - **scheme://domain/path** - Match URIs with this scheme, domain, and exact path
  - **scheme://domain/path/*** - Match URIs with this scheme, domain, and path prefix
  - ***.domain** - Match any URI with a subdomain of this domain

## EXAMPLES

Allow HTTPS URIs for example.com in X.509 certificates on authority level
'''
$ step ca policy authority x509 allow uri-constraint "https://example.com"
'''

Allow HTTPS API URIs with path prefix
'''
$ step ca policy authority x509 allow uri-constraint "https://api.example.com/api/*"
'''

Allow SPIFFE URIs for a specific trust domain
'''
$ step ca policy authority x509 allow uri-constraint "spiffe://trust.domain"
'''

Allow SPIFFE URIs with a specific workload path
'''
$ step ca policy authority x509 allow uri-constraint "spiffe://trust.domain/workload/*"
'''

Deny HTTP (non-secure) URIs
'''
$ step ca policy authority x509 deny uri-constraint "http://"
'''

Remove a constraint
'''
$ step ca policy authority x509 allow uri-constraint "https://example.com" --remove
'''`, commandName),
		Action: command.InjectContext(
			ctx,
			uriConstraintAction,
		),
		Flags: []cli.Flag{
			flags.Provisioner,
			cli.BoolFlag{
				Name:  "remove",
				Usage: `removes the provided URI constraints from the policy instead of adding them`,
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

func uriConstraintAction(ctx context.Context) (err error) {
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
		return errors.New("SSH host policy does not support URI constraints")
	case policycontext.IsSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support URI constraints")
	case policycontext.IsX509Policy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.X509.Allow.UriConstraints = addOrRemoveArguments(policy.X509.Allow.UriConstraints, args, shouldRemove)
		case policycontext.IsDeny(ctx):
			policy.X509.Deny.UriConstraints = addOrRemoveArguments(policy.X509.Deny.UriConstraints, args, shouldRemove)
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
