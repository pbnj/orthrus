package s3

import (
	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	oaws "github.com/go-orthrus/orthrus/checker/aws"
)

// Client returns an AWS S3 client
func Client(account oaws.Account) *s3.S3 {
	log.Debugf("Retrieving AWS API keys for account: %+v", account.Name)
	creds := credentials.NewStaticCredentials(account.AccessKey, account.SecretKey, account.Token)
	creds.Get()
	log.Debugf("Successfully retrieved AWS API keys for account: %+v", account.Name)
	return s3.New(
		session.Must(session.NewSession()),
		aws.NewConfig().WithCredentials(creds))
}

// ClientWithRegion returns an S3 client for a specific region
func ClientWithRegion(account oaws.Account, region string) *s3.S3 {
	log.Debugf("Retrieving AWS API keys for account: %+v", account.Name)
	creds := credentials.NewStaticCredentials(account.AccessKey, account.SecretKey, account.Token)
	creds.Get()
	log.Debugf("Successfully retrieved AWS API keys for account: %+v", account.Name)
	return s3.New(
		session.Must(session.NewSession()),
		aws.NewConfig().WithRegion(region).WithCredentials(creds))
}
