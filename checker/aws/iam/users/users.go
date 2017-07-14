package users

import (
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/service/iam"
	oaws "github.com/go-orthrus/orthrus/checker/aws"
	oiam "github.com/go-orthrus/orthrus/checker/aws/iam"
)

// AU holds slice of users per account.
// AU is used to hold all users per account or to hold a slice of users who are inactive for more than 90 days.
type AU struct {
	Account oaws.Account
	Users   []*iam.User
}

// List enumerates all AWS IAM users
func List(account oaws.Account) *AU {
	userList := &AU{Account: account}
	iamResp, err := oiam.Client(account).ListUsers(&iam.ListUsersInput{})
	if err != nil {
		log.Debugf("Could not list users in account [%s]", account.Name)
		return userList
	}
	log.Debugf("Listed %d users in account [%s]", len(userList.Users), userList.Account.Name)
	userList.Users = iamResp.Users
	return userList
}

// CheckPolicy returns all inactive users per account.
func (au *AU) CheckPolicy(userMaxDays int) *AU {
	log.Debugln("Checking user inactivity in account [%s]", au.Account.Name)

	uc := make(chan *iam.User)
	defer close(uc)

	userMaxDuration := time.Duration(userMaxDays) * 24 * time.Hour
	userViolations := &AU{Account: au.Account}

	for i, user := range au.Users {
		log.Debugf("[%d] Checking if User [%s] is inactive in account [%s]", i, user.UserName, au.Account.Name)
		go func(user *iam.User) {
			uc <- isInactiveUser(user, userMaxDuration)
		}(user)
	}

	for i, user := range au.Users {
		log.Debugf("[%d] Retrieving value from channel for user [%s] in account [%s]", i, user.UserName, au.Account.Name)
		select {
		case v := <-uc:
			if v != nil {
				userViolations.Users = append(userViolations.Users, v)
			}
		}
	}
	return userViolations
}

func isInactiveUser(user *iam.User, userMaxDuration time.Duration) *iam.User {
	// TODO: check to see if user has programmatic access
	if user.PasswordLastUsed != nil {
		hoursSinceLastLogin := time.Since(*user.PasswordLastUsed)
		if hoursSinceLastLogin > userMaxDuration {
			log.Debugf("User [%s] is inactive", *user.UserName)
			return user
		}
	}
	return nil
}
