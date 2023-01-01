/*
Copyright © 2022 Roy Inganta Ginting <ringanta.ginting@gmail.com>
*/
package cmd

import (
	"fmt"

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
		for _, arg := range args {
			fmt.Printf("verify called with key: %s, suffix: %s, arg: %s\n", verificationKey, moduleSignatureSuffix, arg)
		}
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().StringVar(&verificationKey, "key", "", "path to the public key file or KMS URI")
	verifyCmd.MarkFlagRequired("key")
	verifyCmd.Flags().StringVar(&moduleSignatureSuffix, "suffix", ".sig", "suffix for module archive signature")
}
