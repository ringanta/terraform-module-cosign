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
	"strings"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/spf13/cobra"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

var signingKey string
var moduleSignatureSuffix string
var uploadSignature bool

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a Terraform module archive using cosign and save the signature to a file",
	Example: `  terraform-module-cosign sign --key <key path>|<kms uri> <module archive>
	
  # sign Terraform module archive using local private key
  terraform-module-cosign sign --key cosign.key example-module.zip
	
  # sign Terraform module archive using key from AWS KMS
  terraform-module-cosign sign --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] example-module.zip
  
   # sign Terraform module archive on S3 bucket
   terraform-module-cosign sign --key cosign.key s3::https://example-bucket.s3.ap-southeast-1.amazonaws.com/example-module.zip
   
   # sign Terraform module archive on S3 bucket and upload the signature file to the same bucket
   terraform-module-cosign sign --key cosign.key --upload-signature s3::https://example-bucket.s3.ap-southeast-1.amazonaws.com/example-module.zip`,
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

		for _, arg := range args {
			var module, region, bucket, key string

			if strings.HasPrefix(arg, "s3::") {
				// Download module archive from S3 bucket to temporary directory
				s3ObjectUrl := strings.TrimPrefix(arg, "s3::")

				u, err := url.Parse(s3ObjectUrl)
				if err != nil {
					log.Fatalf("Failed to parse url [%s]: %v", s3ObjectUrl, err)
				}

				region, bucket, key, _, err = parseUrl(u)
				if err != nil {
					log.Fatal(err.Error())
				}

				module = path.Base(u.Path)

				s3Downloader, err := newS3Downloader(region)
				if err != nil {
					log.Fatalf("Failed to create S3 downloader: %v", err)
				}

				moduleFile, err := os.Create(module)
				if err != nil {
					log.Fatalf("Failed to create archive on local filesystem: %v", err)
				}
				defer os.Remove(module)

				_, err = s3Downloader.Download(moduleFile, &s3.GetObjectInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(key),
				})
				if err != nil {
					log.Fatalf("Failed to download module archive from S3: %v", err)
				}
			} else {
				module = arg
			}

			// Sign module archive
			moduleSignature := fmt.Sprintf("%s%s", module, moduleSignatureSuffix)
			if _, err := sign.SignBlobCmd(ro, ko, module, true, moduleSignature, "", false); err != nil {
				log.Fatalf("Error signing [%s]: %v", module, err)
			}

			if uploadSignature && strings.HasPrefix(arg, "s3::") {
				signatureKey := strings.Replace(key, module, moduleSignature, 1)

				s3Uploader, err := newS3Uploader(region)
				if err != nil {
					log.Fatalf("Failed to create S3 uploader: %v", err)
				}

				signatureFile, err := os.Open(moduleSignature)
				if err != nil {
					log.Fatalf("Failed to open signature file: %v", err)
				}
				defer os.Remove(moduleSignature)

				_, err = s3Uploader.Upload(&s3manager.UploadInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(signatureKey),
					Body:   signatureFile,
				})
				if err != nil {
					log.Fatalf("Failed to upload signature file to S3: %v", err)
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.Flags().StringVar(&signingKey, "key", "", "path to the private key file or KMS URI")
	signCmd.MarkFlagRequired("key")
	signCmd.Flags().StringVar(&moduleSignatureSuffix, "suffix", ".sig", "suffix for module archive signature")
	signCmd.Flags().BoolVar(&uploadSignature, "upload-signature", false, "whether to upload signature file to remote location")
}

func newS3Downloader(region string) (*s3manager.Downloader, error) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Region: aws.String(region)},
	}))

	downloader := s3manager.NewDownloader(sess)
	return downloader, nil
}

func newS3Uploader(region string) (*s3manager.Uploader, error) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Region: aws.String(region)},
	}))

	Uploader := s3manager.NewUploader(sess)
	return Uploader, nil
}

func parseUrl(u *url.URL) (region, bucket, path, version string, err error) {
	// This just check whether we are dealing with S3 or
	// any other S3 compliant service. S3 has a predictable
	// url as others do not
	if strings.Contains(u.Host, "amazonaws.com") {
		hostParts := strings.Split(u.Host, ".")
		hostPartsLen := len(hostParts)

		switch {
		case hostPartsLen < 3:
			err = fmt.Errorf("URL is not a valid S3 URL")
			return
		case hostPartsLen == 3:
			// Parse the region out of the first part of the host
			region = strings.TrimPrefix(strings.TrimPrefix(hostParts[0], "s3-"), "s3")
			if region == "" {
				region = "us-east-1"
			}

			pathParts := strings.SplitN(u.Path, "/", 3)
			if len(pathParts) != 3 {
				err = fmt.Errorf("URL is not a valid S3 URL")
				return
			}

			bucket = pathParts[1]
			path = pathParts[2]
			version = u.Query().Get("version")
		default:
			bucket = hostParts[0]
			region = hostParts[2]
			path = u.Path
		}

	} else {
		pathParts := strings.SplitN(u.Path, "/", 3)
		if len(pathParts) != 3 {
			err = fmt.Errorf("URL is not a valid S3 complaint URL")
			return
		}
		bucket = pathParts[1]
		path = pathParts[2]
		version = u.Query().Get("version")
		region = u.Query().Get("region")
		if region == "" {
			region = "us-east-1"
		}
	}

	return
}
