package s3

import (
	"context"
	"encoding/json"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	oaws "github.com/go-orthrus/orthrus/checker/aws"
)

type policy struct {
	Statement []statement `json:"Statement"`
	Version   string      `json:"Version"`
}

type statement struct {
	Action    interface{} `json:"Action"`
	Condition interface{} `json:"Condition"`
	Effect    interface{} `json:"Effect"`
	Principal interface{} `json:"Principal"`
	Resource  interface{} `json:"Resource"`
	Sid       interface{} `json:"Sid"`
}

// BucketViolator struct is an object that contains the violating bucket name and the AWS account it exists in.
type BucketViolator struct {
	Account oaws.Account
	Buckets []string
}

// AB represents an account and all its buckets
type AB struct {
	Account oaws.Account
	Buckets []*s3.Bucket
}

// List returns a list of S3 Bucket Policies for all S3 buckets in all regions
func List(account oaws.Account) *AB {
	ab := &AB{Account: account}
	var listParams *s3.ListBucketsInput
	s3Client := ClientWithRegion(account, "us-west-2")
	log.Debugf("Listing Buckets in Account: %s", account.Name)
	buckets, err := s3Client.ListBuckets(listParams)
	if err != nil {
		log.Debugf("Could not list buckets for Account [%s]", account.Name)
		return ab
	}
	log.Debugf("Listed %d Buckets in Account [%s]", len(buckets.Buckets), account.Name)
	ab.Buckets = buckets.Buckets
	return ab
}

// CheckPolicy returns all public buckets for a given account
func (ab *AB) CheckPolicy() *BucketViolator {
	bc := make(chan string)
	defer close(bc) // ensure channel is closed when CheckPolicy function returns/exits

	bv := &BucketViolator{Account: ab.Account}
	if len(ab.Buckets) == 0 {
		return bv
	}

	for i, bucket := range ab.Buckets {
		log.Debugf("[%d] Checking Bucket Policy on bucket [%s] in Account [%s]:", i, *bucket.Name, ab.Account.Name)
		go func(bucket *s3.Bucket) {
			bc <- ab.isPublicBucket(bucket)
		}(bucket)
	}

	for i, b := range ab.Buckets {
		log.Debugln(i, b)
		select {
		case v := <-bc:
			if v != "" {
				bv.Buckets = append(bv.Buckets, v)
			}
		}
	}
	return bv
}

func (ab *AB) isPublicBucket(bucket *s3.Bucket) string {
	log.Debugf("[%s] Checking Bucket Policy on Bucket [%s]", ab.Account.Name, *bucket.Name)
	policyOut, err := getBucketPolicy(*bucket.Name, ab.Account)
	if err != nil {
		log.Debugf("Could not list Bucket Policy for Bucket [%s] in Account [%s]", *bucket.Name, ab.Account.Name)
		return ""
	}
	if isPublic(policyOut, *bucket.Name) {
		return *bucket.Name
	}
	return ""
}

func getBucketPolicy(bucket string, account oaws.Account) (*s3.GetBucketPolicyOutput, error) {
	// defer profile.Duration(time.Now(), "getBucketPolicy function")
	region, err := s3manager.GetBucketRegion(context.Background(), session.Must(session.NewSession()), bucket, "us-east-1")
	if err != nil {
		log.Debugf("Could not retrieve Region for Bucket [%s] in Account [%s]", bucket, account.Name)
		return nil, err
	}
	log.Debugf("Bucket [%s] was found in Region [%s]", bucket, region)
	policyParams := s3.GetBucketPolicyInput{Bucket: aws.String(bucket)}
	policyOutput, err := ClientWithRegion(account, region).GetBucketPolicy(&policyParams)
	if err != nil {
		log.Debugf("Could not retrieve Bucket Policy for Bucket [%s] in Account [%s]: %+v", bucket, account.Name, err)
		return nil, err
	}
	return policyOutput, nil
}

func isPublic(po *s3.GetBucketPolicyOutput, bucket string) bool {
	// defer profile.Duration(time.Now(), "isPublic function")
	if po.Policy == nil {
		return false
	}

	var p policy
	if err := json.Unmarshal([]byte(*po.Policy), &p); err != nil {
		log.Debugf("Could not decipher Bucket Policy JSON: %+v", err)
		return false
	}

	for _, stmt := range p.Statement {
		log.Debugf("Bucket [%s] Policy Statement: %s", bucket, stmt)
		if stmt.Effect == "Allow" && stmt.Action == "s3:GetObject" {
			log.Debugf("Bucket [%s] Statement Effect is ALLOW and Statement Action is S3:GETOBJECT", bucket)
			if pstring, ok := stmt.Principal.(string); ok {
				if pstring == "*" {
					log.Debugf("Prinicpal is *")
					return true
				}
			}
			if pmap, ok := stmt.Principal.(map[string]string); ok {
				if pmap["AWS"] == "*" {
					log.Debugf("Principal is AWS=*")
					return true
				}
			}
		}
		return false
	}

	log.Debugf("Bucket [%s] Policy is empty", bucket)
	return false
}
