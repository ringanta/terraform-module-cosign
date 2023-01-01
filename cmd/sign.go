/*
Copyright © 2022 Roy Inganta Ginting <ringanta.ginting@gmail.com>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var signingKey string
var moduleArchive string
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
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		moduleArchive = args[0]
		moduleSignature := fmt.Sprintf("%s%s", moduleArchive, moduleSignatureSuffix)
		fmt.Printf("sign called with argument %s, will produce signature %s", moduleArchive, moduleSignature)
	},
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.Flags().StringVar(&signingKey, "key", "", "path to the private key file or KMS URI")
	signCmd.MarkFlagRequired("key")
	signCmd.Flags().StringVar(&moduleSignatureSuffix, "suffix", ".sig", "suffix for module archive signature")
}
