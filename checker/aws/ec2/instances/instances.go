package instances

import (
	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/service/ec2"
	oaws "github.com/petermbenjamin/orthrus/checker/aws"
	oec2 "github.com/petermbenjamin/orthrus/checker/aws/ec2"
)

// IV represents instances per account that are violating policies.
type IV struct {
	Account oaws.Account
	Group   []InstanceGroup
}

// InstanceGroup represents instances grouped by region
type InstanceGroup struct {
	Region    string
	Instances []*ec2.Instance
}

// List returns a
func List(account oaws.Account, regions []string) *IV {
	violations := &IV{Account: account}

	c := make(chan *InstanceGroup)
	defer close(c)

	for _, region := range regions {
		ig := &InstanceGroup{Region: region}

		go func(region string) {
			descInstances, err := oec2.ClientWithRegion(account, region).DescribeInstances(&ec2.DescribeInstancesInput{})
			if err != nil {
				c <- ig
			}
			for _, res := range descInstances.Reservations {
				for _, ri := range res.Instances {
					ig.Instances = append(ig.Instances, ri)
				}
			}
			c <- ig
		}(region)
	}

	for ir := range regions {
		logrus.Debugln(ir)
		select {
		case ig := <-c:
			violations.Group = append(violations.Group, *ig)
		}
	}
	return violations
}

// CheckPolicy returns EC2 instances violating policies
func (iv *IV) CheckPolicy() *IV {
	var violations IV
	igc := make(chan *InstanceGroup)
	defer close(igc)
	for _, group := range iv.Group {
		violations.Account = iv.Account
		go func(account oaws.Account, g InstanceGroup) {
			logrus.Debugf("Checking EC2 Policies in Account[%s] in Region [%s]", account.Name, g.Region)
			igv := &InstanceGroup{Region: g.Region}
			if len(g.Instances) == 0 {
				igc <- igv
				return
			}
			for _, i := range g.Instances {
				// logrus.Println(i.SecurityGroups)
				igv.Instances = append(g.Instances, i)
			}
			igc <- igv
		}(iv.Account, group)
	}

	for idx, g := range iv.Group {
		logrus.Debugf("[%d] Looping over instances in Region [%s]", idx, g.Region)
		select {
		case v := <-igc:
			violations.Group = append(violations.Group, *v)
		}
	}

	return &violations
}

func isPublic(i *ec2.Instance) bool {

	return false
}
