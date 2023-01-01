/*
Copyright © 2022 Roy Inganta Ginting <ringanta.ginting@gmail.com>
*/
package cmd

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/spf13/cobra"
)

var verificationKey string

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify Terraform module archive using cosign",
	Example: `  terraform-module-cosign verify --key <key path>|<key url>|<kms uri> <module archive>
  # Verify signature of a Terraform module archive in local file system
  terraform-module-cosign verify --key cosign.pub example-module.zip

  # Verify signature a Terraform module archive on S3 bucket
  terraform-module-cosign verify --key cosign.pub s3::https://example-bucket.s3.ap-southeast-1.amazonaws.com/example-module.zip

  # Verify signature of Terraform modules from a Terraform module
  terraform-module-cosign verify --key cosign.pub .`,
	Args: cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		ko := options.KeyOpts{
			KeyRef: verificationKey,
		}

		verifyModuleArchiveCmd := &verify.VerifyBlobCmd{
			KeyOpts:        ko,
			CertRef:        "",
			IgnoreSCT:      true,
			SCTRef:         "",
			SkipTlogVerify: true,
		}

		for _, arg := range args {
			var modules [1]string

			fmt.Printf("verify called with key: %s, suffix: %s, arg: %s\n", verificationKey, moduleSignatureSuffix, arg)
			if strings.HasPrefix(arg, "s3::") {
				// Todo: Handle verification of Terraform module archive on S3
			} else {
				fileInfo, err := os.Stat(arg)
				if err != nil {
					log.Fatalf("Invalid argument value %s: %v", arg, err)
				}

				if fileInfo.IsDir() {
					// Assume terraform module directory and read module calls
				} else {
					modules[0] = arg
				}
			}

			// Verify module archive
			for _, module := range modules {
				moduleSignature := fmt.Sprintf("%s%s", module, moduleSignatureSuffix)
				verifyModuleArchiveCmd.SigRef = moduleSignature
				if err := verifyModuleArchiveCmd.Exec(cmd.Context(), module); err != nil {
					log.Fatalf("Unexpected error verifying module %s: %v", module, err)
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().StringVar(&verificationKey, "key", "", "path to the public key file or KMS URI")
	verifyCmd.MarkFlagRequired("key")
	verifyCmd.Flags().StringVar(&moduleSignatureSuffix, "suffix", ".sig", "suffix for module archive signature")
}
