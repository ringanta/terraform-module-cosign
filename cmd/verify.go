/*
Copyright © 2022 Roy Inganta Ginting <ringanta.ginting@gmail.com>
*/
package cmd

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
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
				s3ObjectUrl := strings.TrimPrefix(arg, "s3::")
				u, err := url.Parse(s3ObjectUrl)
				if err != nil {
					log.Fatalf("Failed to parse url [%s]: %v", s3ObjectUrl, err)
				}

				region, bucket, key, _, err := parseUrl(u)
				if err != nil {
					log.Fatal(err.Error())
				}

				module := path.Base(u.Path)

				s3Downloader, err := newS3Downloader(region)
				if err != nil {
					log.Fatalf("Failed to create S3 downloader: %v", err)
				}

				tempDir, err := os.MkdirTemp("", "terraform-module-cosign")
				if err != nil {
					log.Fatalf("Failed to create temporary directory: %v", err)
				}
				defer os.RemoveAll(tempDir)

				moduleFile, err := os.Create(filepath.Join(tempDir, module))
				if err != nil {
					log.Fatalf("Failed to create temporary module archive: %v", err)
				}

				_, err = s3Downloader.Download(moduleFile, &s3.GetObjectInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(key),
				})
				if err != nil {
					log.Fatalf("Failed to download module archive from S3: %v", err)
				}

				moduleSignature := fmt.Sprintf("%s%s", module, moduleSignatureSuffix)
				moduleSignatureFile, err := os.Create(filepath.Join(tempDir, moduleSignature))
				if err != nil {
					log.Fatalf("Failed to create temporary module archive signature: %v", err)
				}

				signatureKey := strings.Replace(key, module, moduleSignature, 1)
				_, err = s3Downloader.Download(moduleSignatureFile, &s3.GetObjectInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(signatureKey),
				})
				if err != nil {
					log.Fatalf("Failed to download module archive signature from S3: %v", err)
				}

				modules[0] = moduleFile.Name()
			} else {
				fileInfo, err := os.Stat(arg)
				if err != nil {
					log.Fatalf("Invalid argument value %s: %v", arg, err)
				}

				if fileInfo.IsDir() {
					// Todo: Assume terraform module directory and read module calls
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
