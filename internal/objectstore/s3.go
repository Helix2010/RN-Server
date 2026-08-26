package objectstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Config struct {
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	ForcePathStyle  bool
}

type Client interface {
	PresignPut(context.Context, string, string, int64, time.Duration) (string, map[string]string, error)
	Put(context.Context, string, io.Reader, int64, string) error
	PresignGet(context.Context, string, time.Duration, string) (string, error)
	Head(context.Context, string) (int64, string, error)
	Get(context.Context, string) (io.ReadCloser, error)
	Test(context.Context) error
}

type Factory interface {
	New(Config) (Client, error)
}

type AWSFactory struct{}

func (AWSFactory) New(cfg Config) (Client, error) {
	if strings.TrimSpace(cfg.Region) == "" || strings.TrimSpace(cfg.Bucket) == "" {
		return nil, fmt.Errorf("storage region and bucket are required")
	}
	loadOptions := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(cfg.Region)}
	if cfg.AccessKeyID != "" || cfg.SecretAccessKey != "" {
		if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
			return nil, fmt.Errorf("both storage access key and secret key are required")
		}
		loadOptions = append(loadOptions, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, cfg.SessionToken)))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load storage client configuration: %w", err)
	}
	// Some S3-compatible providers, including Huawei OBS, reject the optional
	// CRC32 streaming trailer that newer AWS SDK versions add to PutObject.
	// Required SigV4 payload signing remains enabled.
	awsCfg.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	// Huawei OBS rejects the optional response checksum mode on presigned GET
	// URLs (InsecureDownloadForbidden). Only validate checksums when an
	// operation explicitly requires one, which keeps downloads compatible with
	// S3-compatible providers while preserving required validation.
	awsCfg.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	if cfg.Endpoint != "" {
		parsed, err := url.Parse(cfg.Endpoint)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return nil, fmt.Errorf("storage endpoint must be an absolute HTTP(S) URL")
		}
		awsCfg.BaseEndpoint = aws.String(strings.TrimRight(cfg.Endpoint, "/"))
	}
	client := s3.NewFromConfig(awsCfg, func(options *s3.Options) {
		options.UsePathStyle = cfg.ForcePathStyle
	})
	return &s3Client{bucket: cfg.Bucket, client: client, presigner: s3.NewPresignClient(client)}, nil
}

type s3Client struct {
	bucket    string
	client    *s3.Client
	presigner *s3.PresignClient
}

func (c *s3Client) PresignPut(ctx context.Context, key, contentType string, size int64, ttl time.Duration) (string, map[string]string, error) {
	output, err := c.presigner.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(c.bucket),
		Key:           aws.String(key),
		ContentLength: aws.Int64(size),
		ContentType:   aws.String(contentType),
	}, func(options *s3.PresignOptions) { options.Expires = ttl })
	if err != nil {
		return "", nil, fmt.Errorf("presign artifact upload: %w", err)
	}
	return output.URL, map[string]string{"content-type": contentType}, nil
}

func (c *s3Client) Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	_, err := c.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(c.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("put artifact: %w", err)
	}
	return nil
}

func (c *s3Client) PresignGet(ctx context.Context, key string, ttl time.Duration, downloadName string) (string, error) {
	disposition := fmt.Sprintf(`attachment; filename="%s"`, strings.ReplaceAll(downloadName, `"`, ""))
	output, err := c.presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket:                     aws.String(c.bucket),
		Key:                        aws.String(key),
		ResponseContentDisposition: aws.String(disposition),
	}, func(options *s3.PresignOptions) { options.Expires = ttl })
	if err != nil {
		return "", fmt.Errorf("presign artifact download: %w", err)
	}
	return output.URL, nil
}

func (c *s3Client) Head(ctx context.Context, key string) (int64, string, error) {
	output, err := c.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
	if err != nil {
		return 0, "", fmt.Errorf("head artifact: %w", err)
	}
	return aws.ToInt64(output.ContentLength), aws.ToString(output.ContentType), nil
}

func (c *s3Client) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	output, err := c.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	return output.Body, nil
}

func (c *s3Client) Test(ctx context.Context) error {
	probeKey := ".rn-foundation-storage-check"
	_, err := c.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(probeKey),
		Body:   bytes.NewReader(nil),
	})
	if err != nil {
		return fmt.Errorf("storage write test failed: %w", err)
	}
	_, err = c.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(probeKey),
	})
	if err != nil {
		return fmt.Errorf("storage read test failed: %w", err)
	}
	return nil
}
