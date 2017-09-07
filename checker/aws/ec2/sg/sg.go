package sg

import (
	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/service/ec2"
	oaws "github.com/petermbenjamin/orthrus/checker/aws"
	oec2 "github.com/petermbenjamin/orthrus/checker/aws/ec2"
)

// SG represents a security group
type SG struct {
	Account   oaws.Account
	GroupSets []Group
}

// Group represents secrutiy groups per region
type Group struct {
	Region  string
	SecGrps []ec2.SecurityGroup
}

// List takes AWS account credentials and regions to return a list of security groups.
func List(account oaws.Account, regions []string) *SG {
	sgs := &SG{Account: account}

	c := make(chan *Group)
	defer close(c)

	for _, region := range regions {
		sg := &Group{Region: region}

		go func(region string) {
			descSecGrps, err := oec2.ClientWithRegion(account, region).DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{})
			if err != nil {
				c <- sg
			}
			for _, g := range descSecGrps.SecurityGroups {
				sg.SecGrps = append(sg.SecGrps, *g)
			}
			c <- sg
		}(region)
	}

	for idx := range regions {
		logrus.Debugln(idx)
		select {
		case sg := <-c:
			sgs.GroupSets = append(sgs.GroupSets, *sg)
		}
	}
	return sgs
}

// CheckPolicy returns Security Groups that allow inbound 0.0.0.0/0
func (sg *SG) CheckPolicy() *SG {
	violations := &SG{Account: sg.Account}
	for _, group := range sg.GroupSets {
		violatingGroup := &Group{Region: group.Region}
		for _, securityGroup := range group.SecGrps {
			for _, inboundRule := range securityGroup.IpPermissions {
				for _, ipRange := range inboundRule.IpRanges {
					if ipRange.CidrIp != nil && *ipRange.CidrIp == "0.0.0.0/0" {
						violatingGroup.SecGrps = append(violatingGroup.SecGrps, securityGroup)
					}
				}
			}
		}
		violations.GroupSets = append(violations.GroupSets, *violatingGroup)
	}
	return violations
}
