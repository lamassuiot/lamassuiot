package keystorager

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/sirupsen/logrus"
)

type AWSS3KeyStorager struct {
	logger     *logrus.Entry
	sdk        *s3.Client
	bucketName string
}

func NewS3Storager(logger *logrus.Entry, awsConf aws.Config, bucket string) (KeyStorager, error) {
	log := logger.WithField("subsystem-provider", "AWS S3 Client")

	httpCli, err := helpers.BuildHTTPClientWithTracerLogger(http.DefaultClient, log)
	if err != nil {
		return nil, err
	}

	awsConf.HTTPClient = httpCli

	s3Client := s3.NewFromConfig(awsConf, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	_, err = s3Client.HeadBucket(context.Background(), &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	exists := true
	if err != nil {
		var apiError smithy.APIError
		if errors.As(err, &apiError) {
			switch apiError.(type) {
			case *types.NotFound:
				log.Infof("Bucket %v is available.\n", bucket)
				exists = false
				err = nil
			default:
				log.Infof("Either you don't have access to bucket %v or another error occurred. "+
					"Here's what happened: %v\n", bucket, err)
				return nil, err
			}
		}
	} else {
		log.Infof("Bucket %v exists.", bucket)
	}

	if !exists {
		_, err = s3Client.CreateBucket(context.Background(), &s3.CreateBucketInput{
			Bucket: &bucket,
		})
		if err != nil {
			return nil, err
		}
	}

	return &AWSS3KeyStorager{
		logger:     log,
		sdk:        s3Client,
		bucketName: bucket,
	}, nil
}

func (engine *AWSS3KeyStorager) Get(keyID string) ([]byte, error) {
	engine.logger.Debugf("Getting the key with ID: %s", keyID)

	result, err := engine.sdk.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: &engine.bucketName,
		Key:    &keyID,
	})
	if err != nil {
		engine.logger.Errorf("could not get Secret Value: %s", err)
		return nil, err
	}

	pemBytes, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, err
	}

	return pemBytes, nil
}

func (engine *AWSS3KeyStorager) Create(keyID string, key []byte) error {
	_, err := engine.sdk.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: &engine.bucketName,
		Key:    &keyID,
		Body:   bytes.NewReader(key),
	})

	if err != nil {
		engine.logger.Error("Could not import the value: ", err)
		return err
	}

	return nil
}

func (engine *AWSS3KeyStorager) Delete(keyID string) error {
	_, err := engine.sdk.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: &engine.bucketName,
		Key:    &keyID,
	})

	if err != nil {
		engine.logger.Error("Could not import private key: ", err)
		return err
	}

	return nil
}
