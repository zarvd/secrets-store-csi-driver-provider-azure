package auth

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/secrets-store-csi-driver-provider-azure/pkg/auth/customtokenproxy"
)

func getIdentityBindingTokenCredential(msiClientID, assertion, aadEndpoint, tenantID string) (azcore.TokenCredential, error) {
	getAssertion := func(context.Context) (string, error) {
		return assertion, nil
	}

	opts := &azidentity.ClientAssertionCredentialOptions{
		ClientOptions: azcore.ClientOptions{
			Cloud: cloud.Configuration{
				ActiveDirectoryAuthorityHost: aadEndpoint,
			},
		},
	}

	if err := customtokenproxy.Configure(&opts.ClientOptions); err != nil {
		return nil, err
	}

	cred, err := azidentity.NewClientAssertionCredential(tenantID, msiClientID, getAssertion, opts)
	if err != nil {
		return nil, err
	}
	return &identityBindingCredential{cred: cred}, nil
}

var _ azcore.TokenCredential = (*identityBindingCredential)(nil)

type identityBindingCredential struct {
	cred *azidentity.ClientAssertionCredential
}

func (c *identityBindingCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return c.cred.GetToken(ctx, opts)
}
