# orthrus

> Security framework and auditing tool for monitoring and analyzing security configurations across multiple environments

![orthrus](orthrus.png)

## DISCLAIMER

This project is still unstable and, thus, **not** production-ready. Breaking changes may be introduced to the API or the CLI.

## Features

- [x] Check public EC2 instances in all regions.
- [x] Check Security Group policies (e.g. inbound 0.0.0.0/0) in all regions.
- [x] Check User MFAs.
- [x] Check User last login date.
- [x] Check public S3 buckets.

## Install

- API
  ```sh
  go get github.com/petermbenjamin/orthrus
  ```

- CLI
  ```sh
  go get github.com/petermbenjamin/orthrus/cmd/orthrus
  ```

## Usage

```sh
$ orthrus --help
usage: orthrus [<flags>] <command> [<args> ...]

A security framework and auditing tool for monitoring, analyzing, and alerting on security configurations across multiple environments.

Flags:
      --help           Show context-sensitive help (also try --help-long and --help-man).
      --version        Show application version.
  -c, --config=CONFIG  Path to config file.
      --debug          Enable debug mode.
      --report         Report violations

Commands:
  help [<command>...]
    Show help.

  ec2 instances
    Check EC2 Instances

  ec2 sg
    Check Security Group

  iam mfa [<flags>]
    Check IAM MFA Policies

  iam user [<flags>]
    Check IAM User Policies

  s3
    Check S3 Policies.

```

## Configuration

- See [sample][sample-config] configuration file.

### AWS

- `orthrus` needs read-only privileges to all AWS services (e.g. EC2, S3, IAM ...etc).

## TODO

- [ ] Refactor into micro-services
- [ ] Dockerize
- [ ] Add more features
- [ ] Add tests

## License

MIT &copy; [Peter Benjamin](https://github.com/petermbenjamin)

[sample-config]: orthrus.sample.yml
