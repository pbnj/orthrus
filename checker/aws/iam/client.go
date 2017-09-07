package iam

import (
	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	oaws "github.com/petermbenjamin/orthrus/checker/aws"
)

// Client instantiates and returns an IAM client
func Client(account oaws.Account) *iam.IAM {
	creds := credentials.NewStaticCredentials(account.AccessKey, account.SecretKey, account.Token)
	creds.Get()
	log.Debugf("Retrieved Credentials for: %+v", account.Name)
	return iam.New(
		session.Must(session.NewSession()),
		aws.NewConfig().WithCredentials(creds))
}
