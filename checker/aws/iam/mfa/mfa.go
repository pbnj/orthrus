package mfa

import (
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/service/iam"
	oaws "github.com/petermbenjamin/orthrus/checker/aws"
	oiam "github.com/petermbenjamin/orthrus/checker/aws/iam"
	"github.com/petermbenjamin/orthrus/checker/aws/iam/users"
)

// MV holds a slice of virtual mfa devices per account.
type MV struct {
	Account   oaws.Account
	VMD       []*iam.VirtualMFADevice
	UserNames []string
}

// MU holds a slice of users per account.
type MU struct {
	Account oaws.Account
	Users   []*iam.User
}

// List returns all AWS Virtual MFA Devices per account
func List(account oaws.Account) *MV {
	mv := &MV{Account: account}
	iamResp, err := oiam.Client(account).ListVirtualMFADevices(&iam.ListVirtualMFADevicesInput{})
	if err != nil {
		log.Debugf("Could not list MFA Devices for account [%s]", account.Name)
		return mv
	}
	log.Debugf("Listed %d Virtual MFA Devices in account [%s]", len(iamResp.VirtualMFADevices), account.Name)
	mv.VMD = iamResp.VirtualMFADevices
	return mv
}

// CheckPolicy will check AWS MFAs against the MFA Policy
// and log violations.
func (mv *MV) CheckPolicy(mfaMaxDays int) *MU {
	log.Debugf("Checking MFA Policy in Account [%s]", mv.Account.Name)

	mc := make(chan MU)
	defer close(mc)

	mfaPolicyMaxDays := time.Duration(mfaMaxDays) * 24 * time.Hour
	mfaViolations := &MU{Account: mv.Account}
	mfaMap := make(map[string]*iam.VirtualMFADevice)

	users := users.List(mv.Account)

	for i, mfa := range mv.VMD {
		log.Debugf("[%d] Checking Virtual MFA Device [%+v] in Account [%s]", i, mfa, mv.Account.Name)
		// some mfa records contain just a serial number, but no User info (indicating user may have had MFA enabled and later disabled it).
		mfaUser := strings.Split(*mfa.SerialNumber, "/")[1]
		mfaMap[mfaUser] = mfa
		if mfa.User == nil {
			log.Debugf("User %s may have disabled MFA!", mfaUser)
			for _, user := range users.Users {
				if mfaUser == *user.UserName {
					mfaViolations.Users = append(mfaViolations.Users, user)
				}
			}
		}
	}

	for _, user := range users.Users {
		if _, ok := mfaMap[*user.UserName]; !ok {
			if user.PasswordLastUsed != nil && time.Since(*user.CreateDate) > mfaPolicyMaxDays {
				log.Debugf("User %+v has not enabled MFA since %+v", *user.UserName, *user.CreateDate)
				mfaViolations.Users = append(mfaViolations.Users, user)
			}
		}
	}
	return mfaViolations
}
