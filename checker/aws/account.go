package aws

// Account struct represents an AWS account and its API access keys
type Account struct {
	Name      string
	Number    string
	AccessKey string
	SecretKey string
	Token     string
}
