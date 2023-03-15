package helppers

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
)

func AWSSessionBuilder(region, accessKeyID, secretAccessKey string) *session.Session {
	sess := session.Must(session.NewSession(&aws.Config{
		Region:      &region,
		Credentials: credentials.NewStaticCredentials(accessKeyID, secretAccessKey, ""),
	}))

	return sess
}
