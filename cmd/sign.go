/*
Copyright © 2022 Roy Inganta Ginting <ringanta.ginting@gmail.com>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/spf13/cobra"
)

var signingKey string
var moduleSignatureSuffix string

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a Terraform module archive using cosign and save the signature to a file",
	Example: `  terraform-module-cosign sign --key <key path>|<kms uri> <module archive>
	
  # sign Terraform module archive using local private key
  terraform-module-cosign sign --key private.key example-module.zip
	
  # sign Terraform module archive using key from AWS KMS
  terraform-module-cosign sign --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] example-module.zip
  
   # sign Terraform module archive on S3 bucket
   terraform-module-cosign sign --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] s3::https://example-bucket.s3.ap-southeast-1.amazonaws.com/example-module.zip`,
	Args: cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		ro := &options.RootOptions{
			OutputFile: "",
			Verbose:    false,
			Timeout:    options.DefaultTimeout,
		}

		ko := options.KeyOpts{
			KeyRef:                   signingKey,
			PassFunc:                 generate.GetPass,
			Sk:                       false,
			Slot:                     "",
			FulcioURL:                "",
			IDToken:                  "",
			InsecureSkipFulcioVerify: false,
			RekorURL:                 "",
			OIDCIssuer:               "",
			OIDCClientID:             "",
			OIDCClientSecret:         "",
			OIDCRedirectURL:          "",
			OIDCDisableProviders:     true,
			BundlePath:               "",
			SkipConfirmation:         true,
			TSAServerURL:             "",
			RFC3161TimestampPath:     "",
		}

		for _, module := range args {
			moduleSignature := fmt.Sprintf("%s%s", module, moduleSignatureSuffix)
			if _, err := sign.SignBlobCmd(ro, ko, module, true, moduleSignature, "", false); err != nil {
				fmt.Printf("Error signing %s: %s", module, err.Error())
				os.Exit(1)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.Flags().StringVar(&signingKey, "key", "", "path to the private key file or KMS URI")
	signCmd.MarkFlagRequired("key")
	signCmd.Flags().StringVar(&moduleSignatureSuffix, "suffix", ".sig", "suffix for module archive signature")
}
