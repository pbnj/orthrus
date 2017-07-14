package ec2

import (
	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	oaws "github.com/go-orthrus/orthrus/checker/aws"
)

// ClientWithRegion instantiates and returns an IAM client in a given region
func ClientWithRegion(account oaws.Account, region string) *ec2.EC2 {
	creds := credentials.NewStaticCredentials(account.AccessKey, account.SecretKey, account.Token)
	creds.Get()
	log.Debugf("Retrieved Credentials for: %+v", account.Name)
	return ec2.New(
		session.Must(session.NewSession()),
		aws.NewConfig().WithCredentials(creds).WithRegion(region))
}
