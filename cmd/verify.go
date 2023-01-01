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
	"github.com/hashicorp/terraform-config-inspect/tfconfig"
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
			var modules []string

			if strings.HasPrefix(arg, "s3::") {
				s3ObjectUrl := strings.TrimPrefix(arg, "s3::")

				tempDir, err := os.MkdirTemp("", "terraform-module-cosign")
				if err != nil {
					log.Fatalf("Failed to create temporary directory: %v", err)
				}
				defer os.RemoveAll(tempDir)

				module, err := getArchiveFromS3(s3ObjectUrl, tempDir)
				if err != nil {
					log.Fatalf("Error downloading module archive from S3: %v", err)
				}

				modules = append(modules, module)
			} else {
				fileInfo, err := os.Stat(arg)
				if err != nil {
					log.Fatalf("Invalid argument value %s: %v", arg, err)
				}

				if fileInfo.IsDir() {
					module, diags := tfconfig.LoadModule(arg)
					if diags != nil {
						log.Fatalf("Failed to read Terraform module directory: %v", diags)
					}

					tempDir, err := os.MkdirTemp("", "terraform-module-cosign")
					if err != nil {
						log.Fatalf("Failed to create temporary directory: %v", err)
					}
					defer os.RemoveAll(tempDir)

					for _, call := range module.ModuleCalls {
						if strings.HasPrefix(call.Source, "s3::") {
							s3ObjectUrl := strings.TrimPrefix(call.Source, "s3::")
							module, err := getArchiveFromS3(s3ObjectUrl, tempDir)
							if err != nil {
								log.Fatal(err)
							}

							modules = append(modules, module)
						}
					}
				} else {
					modules = append(modules, arg)
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

func getArchiveFromS3(moduleUrl, tempDir string) (string, error) {
	s3ObjectUrl := strings.TrimPrefix(moduleUrl, "s3::")
	u, err := url.Parse(s3ObjectUrl)
	if err != nil {
		return "", err
	}

	region, bucket, key, _, err := parseUrl(u)
	if err != nil {
		return "", err
	}

	module := path.Base(u.Path)
	s3Downloader, err := newS3Downloader(region)
	if err != nil {
		return "", err
	}

	modulePath := filepath.Join(tempDir, module)
	moduleFile, err := os.Create(modulePath)
	if err != nil {
		return "", err
	}

	_, err = s3Downloader.Download(moduleFile, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", fmt.Errorf("failed to download module archive %s: %w", key, err)
	}

	moduleSignature := fmt.Sprintf("%s%s", module, moduleSignatureSuffix)
	moduleSignatureFile, err := os.Create(filepath.Join(tempDir, moduleSignature))
	if err != nil {
		return "", err
	}

	signatureKey := strings.Replace(key, module, moduleSignature, 1)
	_, err = s3Downloader.Download(moduleSignatureFile, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(signatureKey),
	})
	if err != nil {
		return "", fmt.Errorf("failed to download module archive signature %s: %v", signatureKey, err)
	}

	return modulePath, nil
}
