package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Sirupsen/logrus"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/nlopes/slack"
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
	VERSION = "0.0.4"
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
	reportFlag = app.Flag("report", "Report violations").Bool()

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
	homeDir, err := homedir.Dir()
	if err != nil {
		viper.AddConfigPath("$HOME/.orthrus")
	}
	viper.AddConfigPath(filepath.Join(homeDir, ".orthrus"))
	viper.SetConfigName("orthrus")
	if err := viper.ReadInConfig(); err != nil {
		logrus.Errorf("could not load configuration file: %v", err)
	}

	accounts = getAccounts()
	regions = getRegions()
}

func main() {

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case iCmd.FullCommand():
		for _, account := range accounts {
			instances := instances.List(account, regions).CheckPolicy()
			var msg string
			for _, e := range instances.Group {
				if len(e.Instances) > 0 {
					msg = fmt.Sprintf("[%s] [%s] %d Instances:\n", account.Name,
						e.Region,
						len(e.Instances))
					for _, i := range e.Instances {
						if i.PublicIpAddress != nil {
							msg += fmt.Sprintf("[%s] [%s] Instance [%s] has Public IP [%s]\n",
								account.Name,
								e.Region,
								*i.InstanceId,
								*i.PublicIpAddress)
						}
					}
					fmt.Println(msg)
				}
				if *reportFlag {
					report(msg)
				}
			}
		}

	case sgCmd.FullCommand():
		for _, account := range accounts {
			secGrps := sg.List(account, regions).CheckPolicy()
			var msg string
			for _, gs := range secGrps.GroupSets {
				if len(gs.SecGrps) > 0 {
					msg += fmt.Sprintf("[%s] [%s] %d Security Groups:\n",
						secGrps.Account.Name,
						gs.Region,
						len(gs.SecGrps))
					for _, sg := range gs.SecGrps {
						msg += fmt.Sprintf("[%s] [%s] Permissions: %+v\n",
							*sg.GroupId,
							*sg.GroupName,
							sg.IpPermissions)
					}
				}
			}
			if *reportFlag {
				report(msg)
			}
			fmt.Println(msg)
		}

	case mfaCmd.FullCommand():
		for _, account := range accounts {
			violations := mfa.List(account).CheckPolicy(mfaMaxDays())
			msg := fmt.Sprintf("[%s] %d Disabled MFAs:\n",
				violations.Account.Name,
				len(violations.Users))
			for _, v := range violations.Users {
				y, m, d := v.CreateDate.Date()
				msg += fmt.Sprintf("[%s] %s (%s)\n",
					violations.Account.Name,
					*v.UserName,
					fmt.Sprintf("%d-%d-%d", y, time.Month(m), d))
			}
			if *reportFlag {
				report(msg)
			}
			fmt.Println(msg)
		}

	case userCmd.FullCommand():
		for _, account := range accounts {
			violations := users.List(account).CheckPolicy(userMaxDays())
			var msg string
			for _, uv := range violations.Users {
				y, m, d := uv.PasswordLastUsed.Date()
				msg += fmt.Sprintf("[%s] %s (%s)\n",
					violations.Account.Name,
					*uv.UserName,
					fmt.Sprintf("%d-%d-%d", y, time.Month(m), d))
			}
			if *reportFlag {
				report(msg)
			}
			fmt.Println(msg)
		}

	case s3Cmd.FullCommand():
		for _, account := range accounts {
			violations := s3.List(account).CheckPolicy()
			msg := fmt.Sprintf("[%s] %d Public Buckets:\n",
				violations.Account.Name,
				len(violations.Buckets))
			for _, b := range violations.Buckets {
				msg += fmt.Sprintf("[%s] %s\n", violations.Account.Name, b)
			}
			if *reportFlag {
				report(msg)
			}
			fmt.Println(msg)
		}
	}

}

func checkErr(err error) {
	if err != nil {
		fmt.Printf("%+v\n", err)
	}
}

func getAccounts() []oaws.Account {
	var accounts []oaws.Account
	accountsMap := viper.GetStringMap("aws.accounts")
	for accountName, creds := range accountsMap {
		accessKey := creds.(map[string]interface{})["aws_access_key_id"].(string)
		secretKey := creds.(map[string]interface{})["aws_secret_access_key"].(string)
		accounts = append(accounts,
			oaws.Account{
				Name:      accountName,
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

func report(data string) {
	api := slack.New(viper.GetString("reporters.slack.token"))
	slackChannel := viper.GetString("reporters.slack.channel")
	respChannel, respTimestamp, err := api.PostMessage(slackChannel,
		data,
		slack.PostMessageParameters{})
	if err != nil {
		fmt.Printf("could not post slack message: %+v\n", err)
	}
	logrus.Debugf("channel response: %+v (%+v)", respChannel, respTimestamp)
}
