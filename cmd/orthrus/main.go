package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Sirupsen/logrus"
	homedir "github.com/mitchellh/go-homedir"
	oaws "github.com/petermbenjamin/orthrus/checker/aws"
	"github.com/petermbenjamin/orthrus/checker/aws/ec2/instances"
	"github.com/petermbenjamin/orthrus/checker/aws/ec2/sg"
	"github.com/petermbenjamin/orthrus/checker/aws/iam/mfa"
	"github.com/petermbenjamin/orthrus/checker/aws/iam/users"
	"github.com/petermbenjamin/orthrus/checker/aws/s3"
	"github.com/spf13/viper"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	// VERSION represents version of app
	VERSION = "0.1.0"
)

var (
	accounts []oaws.Account
	regions  []string
)

var (
	app = kingpin.
		New("orthrus", "A security framework and auditing tool for monitoring, analyzing, and alerting on security configurations across multiple environments.").
		Version(VERSION)

	// outFlag   = app.Flag("out", "Output to file.").Short('o').Bool()
	cfgFlag   = app.Flag("config", "Path to config file.").Short('c').String()
	debugFlag = app.Flag("debug", "Enable debug mode.").
			Action(func(c *kingpin.ParseContext) error {
			logrus.SetLevel(logrus.DebugLevel)
			return nil
		}).Bool()

	// ec2 command
	ec2Cmd = app.Command("ec2", "Check EC2 Policies.").Alias("e")
	iCmd   = ec2Cmd.Command("instances", "Check EC2 Instances").Alias("i")
	sgCmd  = ec2Cmd.Command("sg", "Check Security Group").Alias("s")

	// iam command
	iamCmd          = app.Command("iam", "Check IAM Policies.").Alias("i")
	mfaCmd          = iamCmd.Command("mfa", "Check IAM MFA Policies").Alias("m")
	mfaMaxDaysFlag  = mfaCmd.Flag("mfa-max-days", "Max no. of days users are allowed without MFA.").Int()
	userCmd         = iamCmd.Command("user", "Check IAM User Policies").Alias("u")
	userMaxDaysFlag = userCmd.Flag("user-max-days", "Max no. of days users are inactive.").Int()

	// s3 command
	s3Cmd = app.Command("s3", "Check S3 Policies.")
)

func init() {
	logrus.SetOutput(os.Stdout)

	homeDir, err := homedir.Dir()
	if err != nil {
		viper.AddConfigPath("$HOME/.orthrus")
	}
	viper.AddConfigPath(filepath.Join(homeDir, ".orthrus"))
	viper.SetConfigName("orthrus")
	if err := viper.ReadInConfig(); err != nil {
		logrus.WithField("file", "main.go").Errorf("could not load configuration file: %v", err)
	}

	accounts = getAccounts()
	regions = getRegions()
}

func main() {

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case iCmd.FullCommand():
		for _, account := range accounts {
			instances := instances.List(account, regions).CheckPolicy()
			for _, e := range instances.Group {
				if len(e.Instances) > 0 {
					for _, i := range e.Instances {
						if i.PublicIpAddress != nil {

							logrus.WithFields(logrus.Fields{
								"AccountName":   account.Name,
								"AccountNumber": account.Number,
								"Region":        e.Region,
								"Instance-ID":   *i.InstanceId,
								"Instance-IP":   *i.PublicIpAddress,
								// TODO: Compare Instance SGs with Security Group policies to only report public instances with permissive SG rules
								// "Instance-SG":   i.SecurityGroups,
							}).Warnln("Public Instance IP")

						}
					}
				}
			}
		}

	case sgCmd.FullCommand():
		for _, account := range accounts {
			secGrps := sg.List(account, regions).CheckPolicy()
			for _, gs := range secGrps.GroupSets {
				if len(gs.SecGrps) > 0 {
					for _, sg := range gs.SecGrps {

						logrus.WithFields(logrus.Fields{
							"AccountName":   secGrps.Account.Name,
							"AccountNumber": secGrps.Account.Number,
							"Region":        gs.Region,
							"SG-ID":         *sg.GroupId,
							"SG-Name":       *sg.GroupName,
							"SG-IPs":        sg.IpPermissions,
						}).Warnln("Permissive Security Group")

					}
				}
			}

		}

	case mfaCmd.FullCommand():
		for _, account := range accounts {
			violations := mfa.List(account).CheckPolicy(mfaMaxDays())
			for _, v := range violations.Users {
				y, m, d := v.CreateDate.Date()

				logrus.WithFields(logrus.Fields{
					"AccountName":   violations.Account.Name,
					"AccountNumber": violations.Account.Number,
					"UserName":      *v.UserName,
					"CreateDate":    fmt.Sprintf("%d-%d-%d", y, time.Month(m), d),
				}).Warnln("Disabled MFA")

			}
		}

	case userCmd.FullCommand():
		for _, account := range accounts {
			violations := users.List(account).CheckPolicy(userMaxDays())
			for _, uv := range violations.Users {
				y, m, d := uv.PasswordLastUsed.Date()

				logrus.WithFields(logrus.Fields{
					"AccountName":   violations.Account.Name,
					"AccountNumber": violations.Account.Number,
					"UserName":      *uv.UserName,
					"LogonDate":     fmt.Sprintf("%d-%d-%d", y, time.Month(m), d),
				}).Warnln("Inactive User")

			}
		}

	case s3Cmd.FullCommand():
		for _, account := range accounts {
			violations := s3.List(account).CheckPolicy()
			for _, b := range violations.Buckets {

				logrus.WithFields(logrus.Fields{
					"AccountName":   violations.Account.Name,
					"AccountNumber": violations.Account.Number,
					"BucketName":    b,
				}).Warnln("Public S3 Bucket")

			}
		}
	}

}

func checkErr(err error) {
	if err != nil {
		logrus.WithField("file", "main.go").Errorf("error: %+v\n", err)
	}
}

func getAccounts() []oaws.Account {
	var accounts []oaws.Account
	accountsMap := viper.GetStringMap("aws.accounts")
	for accountName, info := range accountsMap {
		accessKey := info.(map[string]interface{})["aws_access_key_id"].(string)
		secretKey := info.(map[string]interface{})["aws_secret_access_key"].(string)
		accountNumber := info.(map[string]interface{})["number"].(string)
		accounts = append(accounts,
			oaws.Account{
				Name:      accountName,
				Number:    accountNumber,
				AccessKey: accessKey,
				SecretKey: secretKey,
				Token:     ""})
	}
	return accounts
}

func mfaMaxDays() int {
	return viper.GetInt("aws.iam.mfa.policies.max_days")
}

func userMaxDays() int {
	return viper.GetInt("aws.iam.user.policies.max_days")
}

func getRegions() []string {
	return viper.GetStringSlice("aws.regions")
}

// func report(data string) {
// 	api := slack.New(viper.GetString("reporters.slack.token"))
// 	slackChannel := viper.GetString("reporters.slack.channel")
// 	respChannel, respTimestamp, err := api.PostMessage(slackChannel,
// 		data,
// 		slack.PostMessageParameters{})
// 	if err != nil {
// 		fmt.Printf("could not post slack message: %+v\n", err)
// 	}
// 	logrus.Debugf("channel response: %+v (%+v)", respChannel, respTimestamp)
// }
